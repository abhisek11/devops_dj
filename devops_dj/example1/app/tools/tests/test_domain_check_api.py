from django.contrib.auth import get_user_model
from django.urls import reverse
from django.test import TestCase

from rest_framework import status
from rest_framework.test import APIClient

from core.models import Tenant

TOOLS_URL = reverse('tools:domain_check')


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
        Tenant.objects.create(user=self.user, domain='secureyourinbox.com')
        Tenant.objects.create(user=self.user, domain='goshen.com')

        res = self.client.get(TOOLS_URL)
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertTrue(res.data['result'], 'active_domain')
        self.assertTrue(res.data['result'], 'inactive_domain')
