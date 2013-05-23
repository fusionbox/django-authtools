Introduction
============

Before you use this, you should probably read the documentation about :ref:`custom User models <django:auth-custom-user>`.

Installation
------------

1.  Install the package::

        $ pip install django-authuser

    Or you can install it from source::

        $ pip install -e git://github.com/fusionbox/django-authuser@master#egg=django-authuser-dev


Quick Setup
-----------

If you want to use the User model provided by authuser (a sensible choice), there are three short steps.

1.  Add ``authuser`` to your ``INSTALLED_APPS``.

2.  Add the following to your settings.py::

        AUTH_USER_MODEL = 'authuser.User'

3.  Add ``authuser.urls`` to your URL patterns::

        urlpatterns = patterns('',
            # ...
            url(r'^accounts/', include('authuser.urls')),
            # ...
        )

This will set you up with a custom user that

-  uses email as username
-  has one ``name`` field instead of ``first_name``, ``last_name`` (see `Falsehoods Programmers Believe About Names <http://www.kalzumeus.com/2010/06/17/falsehoods-programmers-believe-about-names/>`_)

It also gives you a registered admin class that has a less intimidating
ReadOnlyPasswordHashWidget and the standard auth views (see Views).


But it's supposed to be a *custom* User model!
----------------------------------------------

Making a User model that only concerns itself with authentication and
authorization just *might* be a good idea.  I recommend you read these:

-  `The User-Profile Pattern in Django <http://www.fusionbox.com/blog/detail/the-user-profile-pattern-in-django/>`_
-  `Williams, Master of the "Come From" <https://github.com/raganwald/homoiconic/blob/master/2011/11/COMEFROM.md>`_

Also, please read this quote from the `Django documentation
<https://docs.djangoproject.com/en/1.5/topics/auth/customizing/#specifying-a-custom-user-model>`_:

.. warning::

    Think carefully before handling information not directly related to
    authentication in your custom User Model.

    It may be better to store app-specific user information in a model that has
    a relation with the User model. That allows each app to specify its own
    user data requirements without risking conflicts with other apps. On the
    other hand, queries to retrieve this related information will involve a
    database join, which may have an effect on performance.

However, there are many valid reasons for wanting a User model that you can
change things on.  Django-authuser allows you to that too.  Django-authuser
provides a couple of abstract classes for subclassing.

    :class:`authuser.models.AbstractEmailUser`
      A no-frills email as username model.

    :class:`authuser.models.AbstractNamedUser`
      Adds a name field.

If want to make your custom User model, you can use one of these base classes.

.. tip::

    If you are just adding some methods to the User model, but not changing the
    database fields, you should consider using a proxy model.

If you wanted a User model that had ``full_name`` and ``preferred_name``
fields instead of just ``name``, you could do this::

    from authuser.models import AbstractEmailUser

    class User(AbstractEmailUser):
        full_name = models.CharField('full name', max_length=255, blank=True)
        preferred_name = models.CharField('preferred name',
            max_length=255, blank=True)

        def get_full_name(self):
            return self.full_name

        def get_short_name(self):
            return self.preferred_name
