from django.contrib.auth import get_user_model, authenticate
from django.utils.translation import ugettext_lazy as _
from django.db import transaction
from core.models import Tenant, Profile
from rest_framework import serializers
from custom_exception_message import CustomAPIException
from rest_framework import status


class UserSerializer(serializers.ModelSerializer):
    """Serializer for the user object"""
    company_name = serializers.CharField(required=False)
    primary_domain_name = serializers.CharField(required=False)
    email = serializers.CharField(required=False)
    firstname = serializers.CharField(required=False)
    lastname = serializers.CharField(required=False)
    password = serializers.CharField(
        style={'input_type': 'password'},
        trim_whitespace=False,
        required=False
    )
    user = serializers.CharField(required=False)

    class Meta:
        model = Tenant
        fields = (
            'company_name', 'primary_domain_name', 'email',
            'firstname', 'password', 'user', 'lastname',
            )

    def create(self, validated_data):
        """Create a new user with encrypted password and return it"""
        try:
            company_name = validated_data.pop('company_name')
            primary_domain_name = validated_data.pop('primary_domain_name')
            firstname = validated_data.get('firstname')
            lastname = validated_data.get('lastname')

            if len(validated_data.get('password')) < 8:
                raise CustomAPIException(
                    None,
                    "length of password must be equal or greater than 8 char ",
                    status_code=status.HTTP_400_BAD_REQUEST
                    )

            exists_or_not = get_user_model().objects.filter(
                                    email=validated_data.get(
                                        'email'
                                        )
                                    ).exists()
            if exists_or_not:
                raise CustomAPIException(
                    None,
                    "email already exists",
                    status_code=status.HTTP_400_BAD_REQUEST
                    )

            with transaction.atomic():
                try:
                    user = get_user_model().objects.\
                                    create_user(
                                        email=validated_data.get('email'),
                                        name=firstname+" "+lastname,
                                        password=validated_data.get('password')
                                    )
                    Profile.objects.create(
                        user=user,
                        firstname=firstname,
                        lastname=lastname,
                        email=validated_data.get('email')
                    )

                except Exception:
                    raise CustomAPIException(
                        None,
                        "error ! bad request please check input",
                        status_code=status.HTTP_400_BAD_REQUEST
                    )
                try:
                    if primary_domain_name:
                        Tenant.objects.get_or_create(
                            user=user,
                            company_name=company_name,
                            domain=primary_domain_name
                            )
                    validated_data['company_name'] = company_name
                    validated_data['user'] = user
                    validated_data['primary_domain_name'] = primary_domain_name
                except Exception:
                    raise CustomAPIException(
                        None,
                        "error ! bad request please check input",
                        status_code=status.HTTP_400_BAD_REQUEST
                    )
            validated_data.pop('password')
            return validated_data
        except Exception as e:
            raise e


class AuthTokenSerializer(serializers.Serializer):
    """Serializer for the user authentication object"""
    email = serializers.CharField()
    password = serializers.CharField(
        style={'input_type': 'password'},
        trim_whitespace=False
    )

    def validate(self, attrs):
        """Validate and authenticate the user"""
        email = attrs.get('email')
        password = attrs.get('password')

        user = authenticate(
            request=self.context.get('request'),
            email=email,
            password=password
        )
        if not user:
            msg = _('unable to authenticate with provided credential')
            raise serializers.ValidationError(msg, code='autehntication')

        attrs['user'] = user
        return attrs


class ChangePasswordSerializer(serializers.Serializer):
    """
    Serializer for password change endpoint.
    """
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    confirm_password = serializers.CharField(required=True)

    class Meta:
        model = get_user_model()
        fields = '__all__'


class ForgotPasswordSerializer(serializers.Serializer):
    """
    Serializer for password forgot.
    """
    email_id = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    confirm_password = serializers.CharField(required=True)
    created_by = serializers.CharField(
        default=serializers.CurrentUserDefault())
    owned_by = serializers.CharField(
        default=serializers.CurrentUserDefault())

    class Meta:
        model = get_user_model()
        fields = '__all__'


class TenantAddGetViewSerializer(serializers.ModelSerializer):
    tenants = serializers.ListField(required=False)
    created_by = serializers.CharField(
        default=serializers.CurrentUserDefault())
    owned_by = serializers.CharField(
        default=serializers.CurrentUserDefault())

    class Meta:
        model = Tenant
        fields = ('tenants', 'created_by', 'owned_by')

    def create(self, validated_data):
        try:
            request = self.context.get('request')
            user = request.user
            tenants = validated_data.get('tenants')
            created_by = validated_data.get('created_by')
            owned_by = validated_data.get('owned_by')
            with transaction.atomic():
                for tenant in tenants:
                    industry = tenant.pop(
                                    'industry'
                                    ) if 'industry' in tenant else None
                    regions = tenant.pop(
                                    'regions'
                                    ) if 'regions' in tenant else None
                    exists = Tenant.objects.filter(
                        user=user, domain=tenant.get(
                            'domain')).exists()
                    if exists:
                        raise CustomAPIException(
                            None,
                            "This domain is already taken",
                            status_code=status.HTTP_400_BAD_REQUEST
                        )

                    Tenant.objects.create(
                        user=user, created_by=created_by, owned_by=owned_by,
                        industry_id=industry, regions_id=regions, **tenant
                        )
                return validated_data

        except Exception as e:
            raise e


class ProfileSerializer(serializers.ModelSerializer):

    class Meta:
        model = Profile
        fields = '__all__'


class EditProfileSerializer(serializers.ModelSerializer):
    updated_by = serializers.CharField(
        default=serializers.CurrentUserDefault()
        )
    owned_by = serializers.CharField(default=serializers.CurrentUserDefault())

    class Meta:
        model = Profile
        fields = '__all__'

    def update(self, instance, validated_data):
        try:
            updated_by = validated_data.get('updated_by')
            profile_pic = validated_data.get(
                'profile_pic') if 'profile_pic' in validated_data else None

            with transaction.atomic():
                if profile_pic:
                    instance.firstname = validated_data.get('firstname')
                    instance.lastname = validated_data.get('lastname')
                    instance.profile_pic = profile_pic
                    instance.updated_by = updated_by
                    instance.save()
                else:
                    instance.firstname = validated_data.get('firstname')
                    instance.lastname = validated_data.get('lastname')
                    instance.updated_by = updated_by
                    instance.save()
                return instance
        except Exception as e:
            raise e


class EditTenantSerializer(serializers.ModelSerializer):
    updated_by = serializers.CharField(
        default=serializers.CurrentUserDefault()
        )
    owned_by = serializers.CharField(default=serializers.CurrentUserDefault())

    class Meta:
        model = Tenant
        fields = '__all__'
