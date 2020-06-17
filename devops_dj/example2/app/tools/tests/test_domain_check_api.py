from django.contrib.auth import get_user_model
from django.urls import reverse
from django.test import TestCase

from rest_framework import status
from rest_framework.test import APIClient

from core import models

TOOLS_URL = reverse('tools:domain_check')


def sample_user(email='demo@hatxbot.com', password='testpass'):
    """Create a sample user"""
    return get_user_model().objects.create_user(email, password)


def sample_tenant(org_admin, company_name='brandsecure'):
    """Create a sample user"""
    return models.Tenant.objects.create(
        org_admin=org_admin,
        company_name=company_name
        )


class PublicDomainCheckApiTests(TestCase):
    """Test the publicly available domain status API"""

    def setUp(self):
        self.client = APIClient()

    def test_login_required(self):
        """Test that login is required for retrieving domain status"""
        res = self.client.get(TOOLS_URL)

        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)


class PrivateDomainCheckApiTests(TestCase):
    """Test the authorised user domain status API"""

    def setUp(self):
        self.user = get_user_model().objects.create_user(
            'test@hatxbot.com',
            'password123'
        )
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def test_retrieve_domain_check(self):
        """Test retrieving """
        user = sample_user()
        tenant = sample_tenant(user)
        models.Domains.objects.create(
            tenant=tenant, domain='secureyourinbox.com')
        models.Domains.objects.create(tenant=tenant, domain='goshen.com')

        res = self.client.get(TOOLS_URL)
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertTrue(res.data['result'], 'active_domain')
        self.assertTrue(res.data['result'], 'inactive_domain')
