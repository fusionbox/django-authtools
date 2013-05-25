SECRET_KEY = 'w6bidenrf5q%byf-q82b%pli50i0qmweus6gt_3@k$=zg7ymd3'

INSTALLED_APPS = (
    'django.contrib.sessions',
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'django.contrib.admin',
    'django.contrib.staticfiles',
    'tests',
    'authuser',
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
