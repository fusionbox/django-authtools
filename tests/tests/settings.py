from __future__ import print_function

import os

SECRET_KEY = 'w6bidenrf5q%byf-q82b%pli50i0qmweus6gt_3@k$=zg7ymd3'

INSTALLED_APPS = (
    'django.contrib.sessions',
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'django.contrib.admin',
    'django.contrib.staticfiles',
    'tests',
    'authtools',
)

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': 'sqlite_database',
    }
}

ROOT_URLCONF = 'tests.urls'

STATIC_URL = '/static/'
DEBUG = True

AUTH_USER_MODEL = os.environ.get('AUTH_USER_MODEL', 'auth.User')

print('Using %s as the AUTH_USER_MODEL.' % AUTH_USER_MODEL)
