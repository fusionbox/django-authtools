django-authuser
---------------

A custom user model app for Django 1.5+ that features email as username and
other things. It tries to stay true to the built-in user model for the most
part.

The main differences between authuser's User and django.contrib.auth's are
email as username and class-based auth views.

Read the `django-authuser documentation
<https://django-authuser.readthedocs.org/en/latest/>`_.

Quickstart
==========

Before you use this, you should probably read the documentation about `custom
User models
<https://docs.djangoproject.com/en/dev/topics/auth/customizing/#substituting-a-custom-user-model>`_.

1.  Install the package::

        $ pip install django-authuser

2.  Add ``authuser`` to your ``INSTALLED_APPS``.

3.  Add the following to your settings.py::

        AUTH_USER_MODEL = 'authuser.User'

4.  Add ``authuser.urls`` to your URL patterns::

        urlpatterns = patterns('',
            # ...
            url(r'^accounts/', include('authuser.urls')),
            # ...
        )

5.  Enjoy.
