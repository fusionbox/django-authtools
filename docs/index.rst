django-authtools
================

A custom user model app for Django 1.5+. It tries to stay true to the built-in
User model for the most part.  The main differences between authtools and
django.contrib.auth are a User model with email as username.

It provides its own custom User model, ModelAdmin, and Forms. The Admin classes
and forms, however, are all User model agnostic, so they will work with any
User model.  django-authtools also provides base classes that make creating
your own custom User model easier.

Contents:

.. toctree::
    :maxdepth: 2

    intro
    admin
    forms
    backends
    how-to/index
    talks
    contributing
    changelog

Development
-----------

Development for django-authtools happens on `GitHub
<https://github.com/fusionbox/django-authtools>`_. Pull requests are welcome.
Continuous integration uses `GitHub Actions
<https://github.com/fusionbox/django-authtools/actions>`_.

|Build status|

.. |Build status| image:: https://github.com/fusionbox/django-authtools/actions/workflows/ci.yml/badge.svg
   :target: https://github.com/fusionbox/django-authtools/actions/workflows/ci.yml
   :alt: Build Status
