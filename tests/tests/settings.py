from __future__ import print_function

import os

from django import VERSION as DJANGO_VERSION

SECRET_KEY = 'w6bidenrf5q%byf-q82b%pli50i0qmweus6gt_3@k$=zg7ymd3'
SITE_ID = 1

INSTALLED_APPS = (
    'django.contrib.sessions',
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'django.contrib.admin',
    'django.contrib.staticfiles',
    'django.contrib.sites',
    'tests',
    'authtools',
    'auth_tests',
)

MIDDLEWARE = [
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
]

if DJANGO_VERSION < (1, 10):
    MIDDLEWARE_CLASSES = MIDDLEWARE + [
        'django.contrib.auth.middleware.SessionAuthenticationMiddleware',
    ]


DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': 'sqlite_database',
    }
}

if DJANGO_VERSION[:2] >= (1, 9):
    # django 1.9 introduced the ability to set None to disable migrations.
    MIGRATION_MODULES = {
        'auth': None,
    }
else:
    # This comes from django@1.7#tests/runtests.py
    # This ignores migrations on auth and contenttypes apps
    # (because these modules don't exist)
    MIGRATION_MODULES = {
        'auth': 'django.contrib.auth.tests.migrations',
    }

ROOT_URLCONF = 'tests.urls'

STATIC_URL = '/static/'
DEBUG = True

AUTH_USER_MODEL = os.environ.get('AUTH_USER_MODEL', 'auth.User')

print('Using %s as the AUTH_USER_MODEL.' % AUTH_USER_MODEL)


TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.contrib.auth.context_processors.auth',
            ],
        },
    },
]

# sha1 hasher was removed as a default in django 1.10. Need it for the tests.
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.SHA1PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher',
    'django.contrib.auth.hashers.BCryptSHA256PasswordHasher',
    'django.contrib.auth.hashers.BCryptPasswordHasher',
]
