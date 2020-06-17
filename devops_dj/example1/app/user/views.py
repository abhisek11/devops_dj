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
from core.models import Tenant, Profile, RoleUserMappingTable, \
        RoleMenuMappingTable, Menu
from custom_exception_message import CustomAPIException
from custom_decorator import response_modify_decorator_post, \
        response_modify_decorator_get_after_execution, \
        response_modify_decorator_update
from user.knox_views.views import LoginView as KnoxLoginView, LogoutAllView
from user.serializers import UserSerializer, AuthTokenSerializer, \
        ChangePasswordSerializer, ForgotPasswordSerializer, \
        TenantAddGetViewSerializer, EditProfileSerializer, \
        EditTenantSerializer, ProfileSerializer
from rest_framework.exceptions import APIException


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


class LoginView(KnoxLoginView):
    permission_classes = [AllowAny]
    queryset = get_user_model().objects.all()
    parser_classes = (MultiPartParser, FormParser, JSONParser)

    @response_modify_decorator_post
    def post(self, request, format=None):
        try:
            data = {}
            with transaction.atomic():
                serializer = AuthTokenSerializer(data=request.data)
                serializer.is_valid(raise_exception=True)
                user = serializer.validated_data['user']
                response = super(LoginView, self).post(request, format=None)
                if not user.is_superuser:
                    user_detials = self.queryset.get(email=user)
                    # data['token'] = response.data['token']
                    # data['token_expiry'] = response.data['expiry']
                    # user_detials = User.objects.get(username=user)
                    role = RoleUserMappingTable.objects.filter(user=user_detials.id)
                    menu_details_final=[]
                    if role:
                        role_data= role.get().role
                        role_details={
                            'id':role_data.id,
                            'role_name':role_data.name,
                        }
                        menu_details = RoleMenuMappingTable.objects.filter(
                            role=role_data.id,
                            is_deleted=False
                            ).values(
                                'menu',
                                'menu__name',
                                'menu__url',
                                'menu__parent_id',
                                'menu__icon'
                                )
                        print("menu_details", menu_details)
                        
                        for menu in menu_details:
                            if menu['menu__parent_id'] == 'None':
                                data_dict={
                                    'id':menu['menu'],
                                    'name':menu['menu__name'],
                                    'url':menu['menu__url'] ,
                                    'icon':menu['menu__icon'],
                                    "linkProps": {
                                        "queryParams": {
                                            
                                        }
                                    }
                                }

                                menu_details_final.append(data_dict)
                            else:
                                parent_data = Menu.objects.filter(
                                    id=menu['menu__parent_id']
                                    ).values('id', 'name', 'url', 'icon')
                                print("parent_data",parent_data)
    
                                if parent_data:
                                    check_id = parent_data[0]['id']
                                    print("check_id",check_id)
                                    danger_flag = 0
                                    for check_data in menu_details_final:
                                        if check_data['id'] == check_id:
                                            danger_flag=1
                                    if danger_flag == 0 :
                                        child_list=[]
                                        meta_child={}
                                        data_dict=parent_data[0]
                                        child_data = menu_details.filter(menu__parent_id=menu['menu__parent_id']).values('menu','menu__name','menu__url',
                                            'menu__parent_id','menu__icon','is_create','is_read','is_delete','is_edit')
                                        print("child_data",child_data)
                                        for child in child_data:
                                            meta_child={
                                                'id':child['menu'],
                                                'name':child['menu__name'],
                                                'url':child['menu__url'] ,
                                                'icon':child['menu__url'],
                                                "linkProps": {
                                                    "queryParams": {
                                                        "is_create": menu['is_create'],
                                                        "is_read": menu['is_read'],
                                                        "is_delete": menu['is_delete'],
                                                        "is_edit": menu['is_edit']
                                                    }
                                                }
                                            }
                                            child_list.append(meta_child)
                                        data_dict['children']=child_list
                                        if data_dict not in menu_details_final:
                                            menu_details_final.append(data_dict)

                    else:
                        role_details={}
                        menu_details_final=[]

                    data['token'] = response.data['token']
                    data['token_expiry']=response.data['expiry']
                    data['role_details']=role_details
                    data['menu_details']=menu_details_final
                    data['user_details'] = {
                                "user_id": user_detials.id,
                                "name": user_detials.name,
                                "email": user_detials.email,
                    }

                return Response(data)
        except Exception:
            raise CustomAPIException(
                None, 'Unable to login with provided credential',
                status_code=status.HTTP_400_BAD_REQUEST)


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


class TenantAddGetView(generics.ListCreateAPIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = [TokenAuthentication]
    queryset = Tenant.objects.filter(is_deleted=False)
    serializer_class = TenantAddGetViewSerializer
    parser_classes = (MultiPartParser, FormParser, JSONParser)

    def get_queryset(self):
        user = self.request.user
        return self.queryset.filter(user=user)

    @response_modify_decorator_get_after_execution
    def get(self, request, *args, **kwargs):
        queryset = self.queryset.filter()
        data_list = []
        for data in queryset:
            data_dict = {}
            industry = None if data.industry is None else data.industry.name
            regions = None if data.regions is None else data.regions.name
            data_dict['id'] = data.id
            data_dict['company_name'] = data.company_name
            data_dict['domain'] = data.domain
            data_dict['industry'] = industry
            data_dict['regions'] = regions
            data_list.append(data_dict)
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


class EditTenantView(generics.UpdateAPIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    queryset = Tenant.objects.filter(is_deleted=False)
    serializer_class = EditTenantSerializer

    @response_modify_decorator_update
    def put(self, request, *args, **kwargs):
        return super().put(request, *args, **kwargs)
