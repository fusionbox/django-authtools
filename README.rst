django-authtools
================

|Build status|

.. |Build status| image:: https://github.com/fusionbox/django-authtools/actions/workflows/ci.yml/badge.svg
   :target: https://github.com/fusionbox/django-authtools/actions/workflows/ci.yml
   :alt: Build Status


A custom user model app for Django 2.2+ that features email as username and
other things. It tries to stay true to the built-in user model for the most
part.

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
