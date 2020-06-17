from django.contrib.auth import get_user_model, authenticate
from django.utils.translation import ugettext_lazy as _
from django.db import transaction
from core.models import Tenant, Profile, RoleUserMappingTable, Role, Domains, \
        TenantUserMapping
from rest_framework import serializers
from custom_exception_message import CustomAPIException
from rest_framework import status
from django.contrib.sites.shortcuts import get_current_site
from user.tasks import send_mail_for_account_activation
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from core.utils import generate_token


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
            request = self.context.get('request')
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
                    user.is_active = False
                    user.save()
                    current_site = get_current_site(request)
                    print("current_site", current_site)
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
                        domain_exist = Domains.objects.filter(
                            domain=primary_domain_name).exists()
                        if not domain_exist:
                            tenant, created = Tenant.objects.get_or_create(
                                        org_admin=user,
                                        company_name=company_name,
                                        )
                            Domains.objects.create(
                                tenant=tenant,
                                domain=primary_domain_name
                                )
                            TenantUserMapping.objects.create(
                                tenant=tenant,
                                user=user
                            )
                        else:
                            raise CustomAPIException(
                                None,
                                "sorry! domain " + primary_domain_name +
                                " is already taken ",
                                status_code=status.HTTP_400_BAD_REQUEST
                            )
                    validated_data['company_name'] = company_name
                    validated_data['user'] = user
                    validated_data['primary_domain_name'] = primary_domain_name
                except Exception as e:
                    raise e
            role = Role.objects.filter(name='ADMIN')
            if role:
                role_id = role.get().id
            RoleUserMappingTable.objects.create(
                user=user,
                role_id=role_id
                )
            email = validated_data.get('email')
            name = firstname + " " + lastname
            if current_site.domain.lower() == 'localhost':
                domain = current_site.domain+':8089'
            else:
                domain = current_site.domain
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = generate_token.make_token(user)
            send_mail_for_account_activation.delay(
                email,
                name,
                domain,
                uid,
                token
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
            raise CustomAPIException(
                    None, msg,
                    status_code=status.HTTP_400_BAD_REQUEST)

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


class DomainAddGetViewSerializer(serializers.ModelSerializer):
    domains = serializers.ListField(required=False)
    created_by = serializers.CharField(
        default=serializers.CurrentUserDefault())
    owned_by = serializers.CharField(
        default=serializers.CurrentUserDefault())

    class Meta:
        model = Domains
        fields = ('domains', 'created_by', 'owned_by')

    def create(self, validated_data):
        try:
            request = self.context.get('request')
            user = request.user
            org_admin = Tenant.objects.filter(org_admin=user)
            if org_admin:
                tenant_id = org_admin.get().id
                domains = validated_data.get('domains')
                created_by = validated_data.get('created_by')
                owned_by = validated_data.get('owned_by')
                with transaction.atomic():
                    for domain in domains:
                        exists = Domains.objects.filter(domain=domain).exists()
                        if exists:
                            raise CustomAPIException(
                                None,
                                domain + " domain is already taken",
                                status_code=status.HTTP_400_BAD_REQUEST
                            )

                        Domains.objects.create(
                            tenant_id=tenant_id,
                            domain=domain,
                            created_by=created_by,
                            owned_by=owned_by
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


class EditDomainsSerializer(serializers.ModelSerializer):
    updated_by = serializers.CharField(
        default=serializers.CurrentUserDefault()
        )
    owned_by = serializers.CharField(default=serializers.CurrentUserDefault())

    class Meta:
        model = Domains
        fields = '__all__'
