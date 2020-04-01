django-authtools
================

.. image:: https://travis-ci.org/fusionbox/django-authtools.png
   :target: http://travis-ci.org/fusionbox/django-authtools
   :alt: Build Status


A custom user model app for Django 1.11+ that features email as username and
other things. It tries to stay true to the built-in user model for the most
part.

The main differences between authtools's User and django.contrib.auth's are
email as username and class-based auth views.

Read the `django-authtools documentation
<https://django-authtools.readthedocs.org/en/latest/>`_.

Quickstart
==========

Before you use this, you should probably read the documentation about `custom
User models
<https://docs.djangoproject.com/en/dev/topics/auth/customizing/#substituting-a-custom-user-model>`_.

1.  Install the package:

    .. code-block:: bash

        $ pip install django-authtools

2.  Add ``authtools`` to your ``INSTALLED_APPS``.

3.  Add the following to your settings.py:

    .. code-block:: python

        AUTH_USER_MODEL = 'authtools.User'

4.  Enjoy.
