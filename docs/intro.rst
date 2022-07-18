Introduction
============

Before you use this, you should probably read the documentation about :ref:`custom User models <django:auth-custom-user>`.

Installation
------------

1.  Install the package::

        $ pip install django-authtools

    Or you can install it from source::

        $ pip install -e git+http://github.com/fusionbox/django-authtools@master#egg=django-authtools-dev

2.  Add ``authtools`` to your ``INSTALLED_APPS``.

3.  Run the authtools migrations::

        $ python manage.py migrate


Quick Setup
-----------

If you want to use the User model provided by authtools (a sensible choice), there are three short steps.

1.  Add ``authtools`` to your ``INSTALLED_APPS``.

2.  Add the following to your settings.py::

        AUTH_USER_MODEL = 'authtools.User'

This will set you up with a custom user that

-  uses email as username
-  has one ``name`` field instead of ``first_name``, ``last_name`` (see `Falsehoods Programmers Believe About Names <http://www.kalzumeus.com/2010/06/17/falsehoods-programmers-believe-about-names/>`_)

It also gives you a registered admin class that has a less intimidating
:class:`ReadOnlyPasswordHashWidget <authtools.forms.BetterReadOnlyPasswordHashWidget>`.


But it's supposed to be a *custom* User model!
----------------------------------------------

Making a User model that only concerns itself with authentication and
authorization just *might* be a good idea.  I recommend you read these:

-  `The User-Profile Pattern in Django <https://www.fusionbox.com/blog/detail/the-user-profile-pattern-in-django/560/>`_
-  `Williams, Master of the "Come From" <https://github.com/raganwald/homoiconic/blob/master/2011/11/COMEFROM.md>`_

Also, please read this quote from the `Django documentation
<https://docs.djangoproject.com/en/2.1/topics/auth/customizing/#specifying-a-custom-user-model>`_:

.. warning::

    Think carefully before handling information not directly related to
    authentication in your custom User Model.

    It may be better to store app-specific user information in a model that has
    a relation with the User model. That allows each app to specify its own
    user data requirements without risking conflicts with other apps. On the
    other hand, queries to retrieve this related information will involve a
    database join, which may have an effect on performance.

However, there are many valid reasons for wanting a User model that you can
change things on.  django-authtools allows you to do that too.
django-authtools provides a couple of abstract classes for subclassing.

.. class:: authtools.models.AbstractEmailUser

    A no-frills email as username model that satisifes the User contract and
    the permissions API needed for the Admin site.

.. class:: authtools.models.AbstractNamedUser

    A subclass of :class:`~authtools.models.AbstractEmailUser` that adds a name
    field.

If want to make your custom User model, you can use one of these base classes.

.. tip::

    If you are just adding some methods to the User model, but not changing the
    database fields, you should consider using a proxy model.

If you wanted a User model that had ``full_name`` and ``preferred_name``
fields instead of just ``name``, you could do this::

    from authtools.models import AbstractEmailUser

    class User(AbstractEmailUser):
        full_name = models.CharField('full name', max_length=255, blank=True)
        preferred_name = models.CharField('preferred name',
            max_length=255, blank=True)

        def get_full_name(self):
            return self.full_name

        def get_short_name(self):
            return self.preferred_name

Caveats
-------

There are a couple of limitations to using the User model provided by authtools.

The :class:`~authtools.models.User` provided by authtools specifies an email of ``max_length=255``. This works fine for PostgreSQL, but may cause issues with some other databases (MYSQL, MariaDB) where unique indexes can only be created with 191 characters. For this reason, Django's ``User`` model has a ``username`` field of ``max_length=150``. If you use one of these databases, you may want to subclass :class:`~authtools.models.AbstractEmailUser` or :class:`~authtools.models.AbstractNamedUser` and set the ``username`` field to ``max_length=191``. See the `Django docs <https://docs.djangoproject.com/en/4.0/ref/contrib/auth/#django.contrib.auth.models.User.username>`_ for more about this issue.


Authtools specifies ``DEFAULT_AUTO_FIELD='django.db.models.AutoField'`` to prevent new migrations in existing projects when upgrading to Django >= 3.2. If you want to use ``django.db.models.BigAutoField``, you should subclass :class:`~authtools.models.AbstractEmailUser` or :class:`~authtools.models.AbstractNamedUser`. See the `Django 3.2 release notes <https://docs.djangoproject.com/en/4.0/releases/3.2/#customizing-type-of-auto-created-primary-keys>`_ for more information.
