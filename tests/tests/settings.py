from __future__ import print_function

import os

SECRET_KEY = 'w6bidenrf5q%byf-q82b%pli50i0qmweus6gt_3@k$=zg7ymd3'

INSTALLED_APPS = (
    'django.contrib.sessions',
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'django.contrib.admin',
    'django.contrib.staticfiles',
    'django.contrib.sites',
    'tests',
    'authtools',
)

MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
)

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': 'sqlite_database',
    }
}

# This comes from django@1.7#tests/runtests.py
# This ignores migrations on auth and contenttypes apps
# (because these modules don't exist)
MIGRATION_MODULES = {
    'auth': 'django.contrib.auth.tests.migrations',
    'contenttypes': 'django.contrib.contenttypes.tests.migrations',
}

ROOT_URLCONF = 'tests.urls'

STATIC_URL = '/static/'
DEBUG = True

AUTH_USER_MODEL = os.environ.get('AUTH_USER_MODEL', 'auth.User')

print('Using %s as the AUTH_USER_MODEL.' % AUTH_USER_MODEL)
