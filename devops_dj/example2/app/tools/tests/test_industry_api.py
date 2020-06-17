from django.urls import reverse
from django.test import TestCase

from rest_framework import status
from rest_framework.test import APIClient

from core.models import Industry


INDUSTRY_URL = reverse('tools:industry')


class PublicIndustryApiTests(TestCase):
    """Test the publicly available Industry API"""

    def setUp(self):
        self.client = APIClient()

    def test_no_login_required(self):
        """Test that login is required for retrieving Industry"""
        res = self.client.get(INDUSTRY_URL)

        self.assertEqual(res.status_code, status.HTTP_200_OK)

    def test_retrieve_Industry(self):
        """Test retrieving Industry"""
        Industry.objects.create(name='chemical')

        res = self.client.get(INDUSTRY_URL)

        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data['result'][0]['name'], 'chemical')

    def test_create_industry_successful(self):
        """Test creating a new industry"""
        payload = {'names': ['aerospace']}
        self.client.post(INDUSTRY_URL, payload)

        exists = Industry.objects.filter(
            name=payload['names'][0]
        ).exists()
        self.assertTrue(exists)

    def test_create_industry_invalid(self):
        """Test creating a new industry with invalid payload"""
        payload = {'names': []}
        res = self.client.post(INDUSTRY_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
