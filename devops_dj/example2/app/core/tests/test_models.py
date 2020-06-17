from django.test import TestCase
from django.contrib.auth import get_user_model
from core import models


def sample_user(email='test@hatxbot.com', password='testpass'):
    """Create a sample user"""
    return get_user_model().objects.create_user(email, password)


def sample_tenant(org_admin, company_name='brandsecure'):
    """Create a sample user"""
    return models.Tenant.objects.create(
        org_admin=org_admin,
        company_name=company_name
        )


def sample_menu(**params):
    """Create and return a sample menu"""
    defaults = {
        'name': 'sample recipe',
        'url': 'https://demo/menu/',
        'icon': 'fas fa-video',
    }
    defaults.update(params)

    return models.ParentMenu.objects.create(**defaults)


class ModelTests(TestCase):

    def test_create_user_with_email_successfull(self):
        """Test creating a new user with a mail successful """
        email = 'test@hatxbot.com'
        password = 'testpass123'
        user = get_user_model().objects.create_user(
            email=email, password=password
        )
        self.assertEqual(user.email, email)
        self.assertTrue(user.check_password(password))

    def test_new_user_email_normalized(self):
        """Test the email for a new user is normalized"""
        email = 'test@HATXBOT.COM'
        user = get_user_model().objects.create_user(email, 'test123')

        self.assertEqual(user.email, email.lower())

    def test_new_user_invalid_email(self):
        """Test creating user with raises error"""
        with self.assertRaises(ValueError):
            get_user_model().objects.create_user(None, 'test123')

    def test_create_new_superuser(self):
        """Test creating a new superuser"""
        user = get_user_model().objects.create_superuser(
            'test@hatxbot.com',
            'test123'
        )

        self.assertTrue(user.is_superuser)
        self.assertTrue(user.is_staff)

    def test_industry_str(self):
        """Test the industry string representation"""
        industry = models.Industry.objects.create(
            name='Chemical'
        )

        self.assertEqual(str(industry), industry.name)

    def test_regions_str(self):
        """Test the regions string representation"""
        region = models.Regions.objects.create(
            name='Asia'
        )

        self.assertEqual(str(region), region.name)

    def test_profile_id(self):
        """Test the profile id representation"""

        profile = models.Profile.objects.create(
            user=sample_user(),
            firstname='demo',
            lastname='user',
            email='test@hatxbot.com',
        )

        self.assertEqual(str(profile), str(profile.id))

    def test_tenant_id(self):
        """Test the Tenant id representation"""
        user = sample_user()
        tenant = sample_tenant(user)

        domain = 'testdomain.com'
        tenant = models.Domains.objects.create(
            tenant=tenant,
            domain=domain
        )

        self.assertEqual(str(tenant), str(tenant.id))
        self.assertEqual(domain, tenant.domain)

    def test_menu_str(self):
        """Test the menu str representation"""

        menu = sample_menu()

        self.assertEqual(str(menu), str(menu.name))

    def test_role_str(self):
        """Test the Role str representation"""

        role_name = 'usperadmin'
        role = models.Role.objects.create(
            name=role_name
        )
        self.assertEqual(str(role), str(role.name))

    def test_role_menu_mapping_id(self):
        """Test the Role Menu mapping str representation"""

        role_name = 'superadmin'
        role = models.Role.objects.create(
            name=role_name
        )
        menu = sample_menu()
        rpmam_table = models.RoleParentMenuAcessMappingTable
        role_menu_mapping = rpmam_table.objects.create(
            role=role, parent_menu=menu
        )
        self.assertEqual(str(role_menu_mapping), str(role_menu_mapping.id))
        self.assertEqual(str(role), str(role_menu_mapping.role))

    def test_role_user_mapping_id(self):
        """Test the Role str user mapping representation"""

        role_name = 'usperadmin'
        role = models.Role.objects.create(
            name=role_name
        )
        user = sample_user()
        role_user_mapping = models.RoleUserMappingTable.objects.create(
            user=user,
            role=role
        )
        self.assertEqual(str(role_user_mapping), str(role_user_mapping.id))
        self.assertEqual(str(role), str(role_user_mapping.role))
        self.assertEqual(str(user), str(role_user_mapping.user))
