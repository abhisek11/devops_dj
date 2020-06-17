from django.urls import reverse
from django.test import TestCase

from rest_framework import status
from rest_framework.test import APIClient

from core.models import Regions


REGIONS_URL = reverse('tools:regions')


class PublicRegionsApiTests(TestCase):
    """Test the publicly available Regions API"""

    def setUp(self):
        self.client = APIClient()

    def test_no_login_required(self):
        """Test that login is required for retrieving Regions"""
        res = self.client.get(REGIONS_URL)

        self.assertEqual(res.status_code, status.HTTP_200_OK)

    def test_retrieve_Regions(self):
        """Test retrieving Regions"""
        Regions.objects.create(name='india')

        res = self.client.get(REGIONS_URL)

        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data['result'][0]['name'], 'india')

    def test_create_Regions_successful(self):
        """Test creating a new Regions"""
        payload = {'names': ['australia']}
        self.client.post(REGIONS_URL, payload)

        exists = Regions.objects.filter(
            name=payload['names'][0]
        ).exists()
        self.assertTrue(exists)

    def test_create_Regions_invalid(self):
        """Test creating a new Regions with invalid payload"""
        payload = {'names': []}
        res = self.client.post(REGIONS_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
