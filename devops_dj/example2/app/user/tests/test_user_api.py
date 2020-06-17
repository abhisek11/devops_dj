from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status

CREATE_URSE_URL = reverse('user:create')
TOKEN_URL = reverse('user:token')


def create_user(**params):
    return get_user_model().objects.create_user(**params)


class PublicUserAPITests(TestCase):
    """Test the user API (public)"""

    def setup(self):
        self.client = APIClient()

    def test_user_exists(self):
        """Test creating user that already exists fails"""
        payload = {
                "email": "test@hatxbot.com",
                "password": "testpassword",
                "firstname": "demo",
                "lastname": "user",
                "company_name": "democompany",
                "primary_domain_name": "democompany.com"

            }
        create_user(**{
            'email': 'test@hatxbot.com',
            'password': 'test1234',
            'name': 'test'
            }
        )

        res = self.client.post(CREATE_URSE_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_password_too_short(self):
        """Test that the password must be more than 5 characters"""
        payload = {
                "email": "test@hatxbot.com",
                "password": "pwd",
                "firstname": "demo",
                "lastname": "user",
                "company_name": "democompany",
                "primary_domain_name": "democompany.com"
            }
        res = self.client.post(CREATE_URSE_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        user_exists = get_user_model().objects.filter(
            email=payload['email']
        ).exists()
        self.assertFalse(user_exists)

    def test_create_token_for_user(self):
        """Test that a token is created for the user"""
        payload = {
            'email': 'test@hatxbot.com',
            'password': 'test1234',
        }
        create_user(**payload)
        res = self.client.post(TOKEN_URL, payload)

        self.assertIn('token', res.data)
        self.assertEqual(res.status_code, status.HTTP_200_OK)

    def test_create_token_invalid_credential(self):
        """Test that token is not created if invalid credential are given"""
        create_user(email='test@hatxbot.com', password='test1234')
        payload = {
            'email': 'test@hatxbot.com',
            'password': 'wrong',
        }
        res = self.client.post(TOKEN_URL, payload)
        self.assertNotIn('token', res.data)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_token_no_user(self):
        """Test that token is not created if user dosen't exist"""
        payload = {
            'email': 'test@hatxbot.com',
            'password': 'test12345',
        }
        res = self.client.post(TOKEN_URL, payload)
        self.assertNotIn('token', res.data)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_token_missing_field(self):
        """Test that email and password are required"""
        payload = {
            'email': 'test',
            'password': '',
        }
        res = self.client.post(TOKEN_URL, payload)
        self.assertNotIn('token', res.data)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
