django-authuser
---------------

A custom user model app for Django 1.5+ that features email as username and
other things. It tries to stay true to the built-in user model for the most
part.

The main differences between authuser's User and django.contrib.auth's are

-  email as username
-  one name field instead of first_name, last_name (see
   `Falsehoods Programmers Believe About Names <http://www.kalzumeus.com/2010/06/17/falsehoods-programmers-believe-about-names/>`_)
-  A less intimidating ReadOnlyPasswordHashWidget.

Installation
============

Before you use this, you should probably read the documentation about `custom User models <https://docs.djangoproject.com/en/dev/topics/auth/customizing/#substituting-a-custom-user-model>`_.

1.  Install the package::

        $ pip install -e git://github.com/fusionbox/django-authuser@master#egg=django-authuser-dev

2.  Add ``authuser`` to your ``INSTALLED_APPS``.

3.  Add the following to your settings.py::

        AUTH_USER_MODEL = 'authuser.User'

But it's supposed to be a *custom* user model!
==============================================

Making an auth model that only concerns itself with authentication and
authorization just *might* be a good idea.  I recommend you read these:

-  `The User-Profile Pattern in Django <http://www.fusionbox.com/blog/detail/the-user-profile-pattern-in-django/>`_
-  `Williams, Master of the "Come From" <https://github.com/raganwald/homoiconic/blob/master/2011/11/COMEFROM.md>`_

However, there are many valid reasons for wanting a user model that you can
change things on.  Django-authuser allows you to that too.  Django-authuser
provides a couple of abstract classes for subclassing.

    :class:`authuser.models.AbstractEmailUser`
      A no-frills email as username model.

    :class:`authuser.models.AbstractNamedUser`
      Adds a name field.

If want to make your custom User model, you can use one of these base classes.
You don't need to follow steps 2 or 3 of `Installation`_.

.. note::

    If you are just adding some methods and properties to the User model, you
    should consider using a proxy model.

Admin
=====

Django-authuser provides a couple of Admin classes.  The default one is
:class:`authuser.admin.NamedUserAdmin`, which provides an admin similar to
:class:`django.contrib.auth`.  If you are not using the
:class:`AbstractNamedUser`, you might want the :class:`authuser.admin.UserAdmin`
instead.  In addition there is a :class:`StrippedUserAdmin` and a
:class:`StrippedNamedUserAdmin` class that don't include the Important Dates
section or the permission models if you want simpler versions of those.

If you are using your own user model, authuser won't register an Admin class to
avoid problems.  If you define ``REQUIRED_FIELDS`` on your custom model, authuser
will add those to the first fieldset.

Forms
=====

Authuser provides the following Form classes:

    :class:`authuser.forms.UserCreationForm`
      Basically the same as django.contrib.auth, but respects ``USERNAME_FIELD``
      and ``User.REQUIRED_FIELDS``.

    :class:`authuser.forms.UserChangeForm`
      A normal ModelForm that adds a ``ReadOnlyPasswordHashField`` with the
      ``BetterReadOnlyPasswordHashWidget``.

.. currentmodule:: authuser.views

Views
=====

Authuser provides the following Class-based views, intended to be *mostly*
drop-in replacements for their :class:`django.contrib.auth.views` counterparts.

.. class:: authuser.views.LoginView
    **view function:** :func:`authuser.views.login`
    **replaces:** :func:`django.contrib.auth.views.login`.

    .. note::

    - New property ``disallow_authenticated`` which defaults to ``True``.  When
      true, authenticated users will be automatically redirected to the
      ``success_url`` when visiting this view.

.. class:: authuser.views.LogoutView
    **view function:** :func:`authuser.views.logout`
    **replaces:** :func:`django.contrib.auth.views.logout`.

    .. note::

    - The ``next_page`` parameter has been replaced with ``success_url`` to
      comply with the Class-based views api.


.. class:: authuser.views.LogoutThenLoginView
    **view function:** :func:`authuser.views.logout_then_login`
    **replaces:** :func:`django.contrib.auth.views.logout_then_login`.

    .. note::

    - The ``login_url`` parameter has been replaced with ``success_url`` to
      comply with the Class-based views api.

.. class:: authuser.views.PasswordChange`
    **view function:** :func:`authuser.views.password_change`
    **replaces:** :func:`django.contrib.auth.views.password_change`.

    .. note::

    - The ``post_change_redirect`` parameter has been replaced with
      ``success_url`` to comply with the Class-based views api.

.. class:: authuser.views.PasswordChangeDone
    **view function:** :func:`authuser.views.password_change_done`
    **replaces:** :func:`django.contrib.auth.views.password_change_done`.

.. class:: authuser.views.PasswordResetView
    **view function:** :func:`authuser.views.password_reset`
    **replaces:** :func:`django.contrib.auth.views.password_reset`.

    .. note::

    - The ``next_page` parameter has been replaced with ``success_url`` to
      comply with the Class-based views api.
    - The ``password_reset_form`` parameter has been replaced with
      ``form_class`` to comply with the Class-based views api.
    - The password reset email is no longer sent from
      ``PasswordResetForm.save()``.  The method
      :class:`PasswordResetView.send_password_reset_email` is passed the
      ``user`` as the sole argument and is responsible for sending the reset
      email.  This method simply duplicates the logic found on
      :class:`django.contrib.auth.forms.PasswordResetForm` and can be overidden
      via subclassing the view class.


.. class:: authuser.views.PasswordResetDoneView
    **view function:** :func:`authuser.views.password_reset_done`
    **replaces:** :class:`django.contrib.auth.views.password_reset_done`.

.. class:: authuser.views.PasswordResetConfirmView
    **view function:** :func:`authuser.views.password_reset_confirm`
    **replaces:** :func:`django.contrib.auth.views.password_reset_confirm`.

    .. note::

    - The ``set_password_form`` parameter has been replaced with ``form_class``
      to comply with the Class-based views api.
    - The ``post_reset_redirect`` parameter has been replaced with
      ``success_url`` to comply with the Class-based views api.

.. class:: authuser.views.PasswordResetCompleteView
    **view function:** :func:`authuser.views.password_reset_complete`
    **replaces:** :func:`django.contrib.auth.views.password_reset_complete`.
