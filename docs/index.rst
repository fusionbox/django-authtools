django-authuser
===============

A custom user model app for Django 1.5+. It tries to stay true to the built-in
User model for the most part.  The main differences between authuser and
django.contrib.auth are a User model with email as username and classed-based
auth views.

It provides its own custom User model, views, urls, ModelAdmin, and Forms. The
Admin classes, views, and forms, however, are all User model agnostic, so they
will work with any User model.  django-authuser also provides base classes that
make creating your own custom User model easier.

Contents:

.. toctree::
    :maxdepth: 2

    intro
    admin
    forms
    views

Development
-----------

Development for django-authuser happens on `GitHub
<https://github.com/fusionbox/django-authuser>`_. Pull requests are welcome.
Continuous integration is hosted on `Travis CI
<https://travis-ci.org/fusionbox/django-authuser>`_.

.. image:: https://travis-ci.org/fusionbox/django-authuser.png
   :target: http://travis-ci.org/fusionbox/django-authuser
   :alt: Build Status
