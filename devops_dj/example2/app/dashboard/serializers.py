from django.db import transaction
from core import models
from rest_framework import serializers
from custom_exception_message import CustomAPIException
from rest_framework import status


class DashboardUserCreateViewSerializer(serializers.ModelSerializer):
    created_by = serializers.CharField(
        default=serializers.CurrentUserDefault())
    owned_by = serializers.CharField(default=serializers.CurrentUserDefault())
    role = serializers.CharField(required=False)
    firstname = serializers.CharField(required=False)
    lastname = serializers.CharField(required=False)
    groups = serializers.ListField(required=False)
    user_permissions = serializers.ListField(required=False)
    name = serializers.CharField(required=False)
    password = serializers.CharField(
        write_only=True,
        required=False,
        help_text='Leave empty if no change needed',
        style={'input_type': 'password', 'placeholder': 'Password'}
    )
    confirm_password = serializers.CharField(
        write_only=True,
        required=False,
        help_text='Leave empty if no change needed',
        style={'input_type': 'password', 'placeholder': 'Password'}
    )

    class Meta:
        model = models.User
        fields = '__all__'

    def create(self, validated_data):
        try:
            request = self.context.get('request')
            created_by = validated_data.get('created_by')
            owned_by = validated_data.get('owned_by')
            is_admin = models.RoleUserMappingTable.objects.filter(
                user=request.user).values_list('role__name', flat=True)
            with transaction.atomic():
                firstname = validated_data.get(
                    'firstname'
                    ) if validated_data.get('firstname') else ""
                lastname = validated_data.get(
                    'lastname'
                    ) if validated_data.get('lastname') else ""
                email = validated_data.get(
                    'email'
                    ) if validated_data.get('email') else None
                password = validated_data.get(
                    'password'
                    ) if validated_data.get('password') else None
                confirm_password = validated_data.get(
                    'confirm_password'
                    ) if validated_data.get('confirm_password') else None
                role = validated_data.get(
                    'role'
                    ) if validated_data.get('role') else ""
                if email is None or password is None:
                    raise CustomAPIException(
                            None,
                            "Please provide both email and password ",
                            status_code=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    if password == confirm_password:
                        if models.User.objects.filter(email=email).exists():
                            raise CustomAPIException(
                                None,
                                "Email ID already exist ",
                                status_code=status.HTTP_409_CONFLICT
                                )
                        else:
                            if 'ADMIN' in is_admin:
                                user = models.User.objects.create_user(
                                    email=email,
                                    name=firstname+' '+lastname
                                    )
                                user.set_password(password)
                                user.is_active = True
                                user.save()

                                models.Profile.objects.create(
                                    user=user,
                                    firstname=firstname,
                                    lastname=lastname,
                                    email=validated_data.get('email')
                                )

                                models.RoleUserMappingTable.\
                                    objects.create(
                                        user=user,
                                        role_id=role,
                                        created_by=created_by,
                                        owned_by=owned_by
                                        )
                            else:
                                raise CustomAPIException(
                                    None,
                                    "Access denied !",
                                    status_code=status.HTTP_409_CONFLICT
                                    )
                    else:
                        raise CustomAPIException(
                                None,
                                "Password did not matched",
                                status_code=status.HTTP_409_CONFLICT
                                )

                validated_data['is_active'] = user.is_active
                validated_data['user'] = {
                    'user_id': user.__dict__['id'],
                    'user_email': user.__dict__['email']
                }

                return validated_data

        except Exception as e:
            raise e


class DashboardDynamicMenuViewSerializer(serializers.ModelSerializer):
    user = serializers.CharField(required=False)
    right_menu = serializers.ListField(required=False)
    left_menu = serializers.ListField(required=False)

    class Meta:
        model = models.RoleUserMappingTable
        fields = ('user', 'role', 'right_menu', 'left_menu')
