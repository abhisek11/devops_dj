"""
Django settings for app project.

Generated by 'django-admin startproject' using Django 3.0.5.

For more information on this file, see
https://docs.djangoproject.com/en/3.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/3.0/ref/settings/
"""

import os
import sentry_sdk
from sentry_sdk.integrations.django import DjangoIntegration
from sentry_sdk.integrations.celery import CeleryIntegration
from sentry_sdk.integrations.redis import RedisIntegration
from datetime import timedelta

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

SECRET_KEY = os.environ.get("SECRET_KEY")
ENV_CELERY_BROKER_URL = os.environ.get("CELERY_BROKER_URL")
if not ENV_CELERY_BROKER_URL or  len(ENV_CELERY_BROKER_URL) == 0:
    ENV_CELERY_BROKER_URL = "redis://redis:6379"

# SECRET_KEY = 'a-e#vt$%$-=30$2d+d^1-9dg4ekhh4^i)$y8axs136g^c3uyqw'
DEBUG = int(os.environ.get("DEBUG", default=0))
# DEBUG = True
ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS").split(" ")
# ALLOWED_HOSTS = ['*']

REST_KNOX = {
    'TOKEN_TTL': timedelta(hours=8),
    'AUTO_REFRESH': False,
}

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'corsheaders',
    'rest_framework',
    'rest_framework.authtoken',
    'core',
    'user',
    'knox',
    'tools',

]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

CORS_ORIGIN_ALLOW_ALL = True
ROOT_URLCONF = 'app.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'app.wsgi.application'


# Database
# https://docs.djangoproject.com/en/3.0/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': os.environ.get('DB_ENGINE'),
        'HOST': os.environ.get('DB_HOST'),
        'PORT': os.environ.get('DB_PORT'),
        'NAME': os.environ.get('DB_NAME'),
        'USER': os.environ.get('DB_USER'),
        'PASSWORD': os.environ.get('DB_PASSWORD'),
    }
}



# Password validation
# https://docs.djangoproject.com/en/3.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/3.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.0/howto/static-files/

STATIC_URL = '/static/'
STATIC_ROOT =  os.path.join(BASE_DIR, 'static')

MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

AUTH_USER_MODEL = 'core.User'

# ============= Error Msg configrations =================
MSG_SUCCESS="Success"
MSG_NO_DATA="No Data Found"
MSG_ERROR="Failure"

REDIRECT_URL = 'https://app.dev.secureyourinbox.net/'

#===============Email================================#
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_FROM_C = 'no-reply@secureyourinbox.com'
DEFAULT_FROM_EMAIL = 'no-reply@secureyourinbox.com'
SERVER_EMAIL = 'no-reply@secureyourinbox.com'
SENDGRID_API_KEY = os.environ.get('SENDGRID_API_KEY')
EMAIL_HOST = 'smtp.sendgrid.net'
EMAIL_HOST_USER = 'apikey'
EMAIL_HOST_PASSWORD = SENDGRID_API_KEY
EMAIL_PORT = 587
EMAIL_USE_TLS = True
#================Sentry ===================================#
if not DEBUG:
    sentry_sdk.init(
        dsn="https://ef1427ed0ee54689b955f7da74c15529@o389275.ingest.sentry.io/5227264",
        integrations=[
            DjangoIntegration(),
            CeleryIntegration(),
            RedisIntegration(),
            ],
        # If you wish to associate users to errors (assuming you are using
        # django.contrib.auth) you may enable sending PII data.
        send_default_pii=True
    )

#====================Celery=====================================#
from celery.schedules import crontab
from django import db

# CELERY_BROKER_URL = 'amqp://admin:mypass@rabbitmq:5672'
#CELERY_BROKER_URL = 'redis://redis:6379'
CELERY_BROKER_URL = ENV_CELERY_BROKER_URL
#CELERY_RESULT_BACKEND = 'redis://redis:6379'
CELERY_RESULT_BACKEND = ENV_CELERY_BROKER_URL
CELERY_CACHE_BACKEND = 'default'

# django setting.
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.db.DatabaseCache',
        'LOCATION': 'my_cache_table',
    }
}
CELERY_ACCEPT_CONTENT = ['application/json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'

CELERY_BEAT_SCHEDULE = {
    'queue_every_1_mins': {
        'task': 'tools.tasks.hello',
        'schedule': crontab(minute=0, hour=0),
        # 'schedule':10,
    },
    'Check_domain_status_midnight': {
        'task': 'tools.tasks.domain_check',
        'schedule': crontab(minute=0, hour=0),
        # 'schedule':10,
    },
}

#===================ADMIN Settings==============================

ADMIN_ORDERING = [

    ('core', [
        'User',
        'Profile',
        'Tenant',
        'Domains',
        'TenantUserMapping',
        'ParentMenu',
        'ChildMenu',
        'Role',
        'Access',
        'RoleParentMenuAcessMappingTable',
        'RoleUserMappingTable',
        'ReportDumpUploadbkp',
        'ReportFeedbackMetaData',
        'ReportFeedbackRecord',
        'ReportFeedbackRecordAuthResultsDkim',
        'ReportFeedbackRecordAuthResultsSpf',
        'MailTemplate',
        'Industry',
        'Regions',
    ]),
    ('knox', [
        'AuthToken'
    ]),
]

def get_app_list(self, request):
    app_dict = self._build_app_dict(request)
    for app_name, object_list in ADMIN_ORDERING:
        app = app_dict[app_name]
        app['models'].sort(key=lambda x: object_list.index(x['object_name']))
        yield app


# Covering django.contrib.admin.AdminSite.get_app_list
from django.contrib import admin

admin.AdminSite.get_app_list = get_app_list
