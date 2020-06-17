from rest_framework import generics
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.settings import api_settings
from django.db import transaction
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.contrib.auth import get_user_model
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework.response import Response
from knox.auth import TokenAuthentication
from rest_framework import status
from core.models import Tenant, Profile, User, Domains
# RoleUserMappingTable, RoleMenuMappingTable, Menu
from custom_exception_message import CustomAPIException
from custom_decorator import response_modify_decorator_post, \
        response_modify_decorator_get_after_execution, \
        response_modify_decorator_update
from user.knox_views.views import LoginView as KnoxLoginView, LogoutAllView
from user.serializers import UserSerializer, AuthTokenSerializer, \
        ChangePasswordSerializer, ForgotPasswordSerializer, \
        DomainAddGetViewSerializer, EditProfileSerializer, \
        EditDomainsSerializer, ProfileSerializer
from rest_framework.exceptions import APIException
from user.tasks import send_mail_forgot_password
from django.utils.http import urlsafe_base64_decode
from app.settings import REDIRECT_URL as redirect_url
from django.shortcuts import redirect
from django.utils.encoding import force_text
from core.utils import generate_token


def activate(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(id=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and generate_token.check_token(user, token):
        user.is_active = True
        user.save()
        return redirect(
            redirect_url,
            'Thank you for your email confirmation. \
            Now you can login your account.'
            )
    else:
        return redirect('Activation link is invalid!')


class CreateUserView(generics.CreateAPIView):
    """Create a new user in system"""
    permission_classes = [AllowAny]
    queryset = Tenant.objects.all()
    serializer_class = UserSerializer
    parser_classes = (MultiPartParser, FormParser, JSONParser)

    @response_modify_decorator_post
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)


class CreateTokenView(ObtainAuthToken):
    """Create a new auth token for user"""
    serializer_class = AuthTokenSerializer
    render_classes = api_settings.DEFAULT_RENDERER_CLASSES


class EmailForgotPassword(generics.ListCreateAPIView):
    permission_classes = [AllowAny]

    def post(self, request, format=None):
        try:
            with transaction.atomic():
                email = request.data["email"]
                exist = User.objects.filter(email=email)
                if exist:
                    name = exist.get().name
                    send_mail_forgot_password.delay(name, email)
                    return Response(
                        {
                            'request_status': 1,
                            'msg': 'please check your mailid'
                        },
                        status=status.HTTP_200_OK)
                else:
                    raise CustomAPIException(
                        None, 'Email address does not belong to any account',
                        status_code=status.HTTP_404_NOT_FOUND)

        except ValueError as v:
            return v


class LoginView(KnoxLoginView):
    permission_classes = [AllowAny]
    queryset = get_user_model().objects.all()
    parser_classes = (MultiPartParser, FormParser, JSONParser)

    @response_modify_decorator_post
    def post(self, request, format=None):
        data = {}
        with transaction.atomic():
            user_is_active = self.queryset.filter(
                email=request.data['email'],
                is_active=True)
            if not user_is_active:
                raise CustomAPIException(
                    None, 'sorry, Account is not active !',
                    status_code=status.HTTP_400_BAD_REQUEST)
            serializer = AuthTokenSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            user = serializer.validated_data['user']
            response = super(LoginView, self).post(request, format=None)
            if not user.is_superuser:
                user_detials = self.queryset.get(email=user)
                data['token'] = response.data['token']
                data['token_expiry'] = response.data['expiry']
                data['user_details'] = {
                            "user_id": user_detials.id,
                            "name": user_detials.name,
                            "email": user_detials.email,
                }

            return Response(data)


class ChangePasswordView(generics.UpdateAPIView):
    """
    For changing password.
    password is changing using login user token.
    needs old password and new password,
    check old password is exiest or not
    if exiest than it works
    """
    permission_classes = (IsAuthenticated,)
    authentication_classes = [TokenAuthentication]
    serializer_class = ChangePasswordSerializer

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)
        with transaction.atomic():

            if serializer.is_valid():
                if not self.object.check_password(
                    serializer.data.get(
                        "old_password"
                        )
                ):
                    return Response({
                        'request_status': 0,
                        'result': {'msg': "Old password does not match ..."}
                        }, status=status.HTTP_400_BAD_REQUEST
                    )
                if len(serializer.data.get("new_password")) < 8:
                    return Response({
                        'request_status': 0,
                        'result': {
                            'msg': "length of password must be equal\
                             or greater than 8 char"
                            }
                        }, status=status.HTTP_400_BAD_REQUEST)
                new_password = serializer.data.get("new_password")
                confirm_password = serializer.data.get("confirm_password")
                print("new_password", new_password, confirm_password)
                if new_password == confirm_password:
                    self.object.set_password(
                        serializer.data.get("new_password"))
                    self.object.save()
                    LogoutAllView.post(self, request)
                    return Response(
                        {
                            'request_status': 1,
                            'result': {
                                'msg': "New Password Save Success..."}
                        }, status=status.HTTP_200_OK)
                else:
                    return Response(
                        {
                            'request_status': 0,
                            'result': {
                                'msg': "new password do not match"}
                        }, status=status.HTTP_400_BAD_REQUEST)
            return Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
                )


class ForgotPasswordView(generics.ListCreateAPIView):
    """
    Forgot password using phone ,
    otp send , after verification,
    user can set new password
    using post method
    """

    permission_classes = [AllowAny]
    queryset = get_user_model().objects.all()
    serializer_class = ForgotPasswordSerializer

    @response_modify_decorator_post
    def post(self, request, *args, **kwargs):
        user = self.queryset
        if request.data.get('email_id'):
            email_id = request.data['email_id']
        else:
            email_id = None
        new_password = request.data['new_password']
        confirm_password = request.data['confirm_password']
        try:
            if email_id:
                user_details_exiest = self.queryset.get(email=email_id).id

        except(TypeError, ValueError, OverflowError,
                get_user_model().DoesNotExist):
            raise CustomAPIException(
                None, 'Matching User does not exist !',
                status_code=status.HTTP_404_NOT_FOUND)
        print("user_details_exiest", user_details_exiest)
        if user_details_exiest:
            if new_password == confirm_password:
                user = user.get(id=user_details_exiest)
                if not user.check_password(new_password):
                    user.set_password(new_password)  # set password...
                    user.save()
                else:
                    msg = 'Your new password is similar to old password.\
                             Please try with another password.'
                    raise CustomAPIException(
                        None, msg, status_code=status.HTTP_409_CONFLICT)
            return Response(
                {
                    'request_status': 1,
                    'result':
                        {
                            'msg': "New Password Save Success..."
                        }
                    }, status=status.HTTP_200_OK
                )
        else:
            raise APIException(
                {
                    'request_status': 0,
                    'result': {'msg': "User does not exist."}
                        }
            )


class DomainAddGetView(generics.ListCreateAPIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = [TokenAuthentication]
    queryset = Domains.objects.filter(is_deleted=False)
    serializer_class = DomainAddGetViewSerializer
    parser_classes = (MultiPartParser, FormParser, JSONParser)

    def get_queryset(self):
        user = self.request.user
        return self.queryset.filter(
            tenant__tenantusermapping__user=user)

    @response_modify_decorator_get_after_execution
    def get(self, request, *args, **kwargs):
        queryset = self.queryset.filter()
        data_list = []
        for data in queryset:
            data_list.append(data.domain)
        return Response(data_list)

    @response_modify_decorator_post
    def post(self, request, *args, **kwargs):
        return super(self.__class__, self).post(request, *args, **kwargs)


class ProfileView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    queryset = Profile.objects.filter(is_deleted=False)
    serializer_class = ProfileSerializer

    def get_queryset(self):
        user = self.request.user
        return self.queryset.filter(user=user)

    @response_modify_decorator_get_after_execution
    def get(self, request, *args, **kwargs):
        return super(self.__class__, self).get(request, *args, **kwargs)


class EditProfileView(generics.UpdateAPIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    queryset = Profile.objects.filter(is_deleted=False)
    serializer_class = EditProfileSerializer

    @response_modify_decorator_update
    def put(self, request, *args, **kwargs):
        return super().put(request, *args, **kwargs)


class EditDomainView(generics.UpdateAPIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    queryset = Domains.objects.filter(is_deleted=False)
    serializer_class = EditDomainsSerializer

    @response_modify_decorator_update
    def put(self, request, *args, **kwargs):
        return super().put(request, *args, **kwargs)
