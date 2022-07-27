Forms
=====

.. currentmodule:: authtools.forms

django-authtools provides several Form classes that mimic the forms in
django.contrib.auth.forms, but work better with ``USERNAME_FIELD`` and
``REQUIRED_FIELDS``.  These forms don't require the
:class:`authtools.models.User` class in order to work, they should work with any
User model that follows the :class:`User class contract <django:django.contrib.auth.models.CustomUser>`.

.. class:: UserCreationForm

    Basically the same as django.contrib.auth, but respects ``USERNAME_FIELD``
    and ``User.REQUIRED_FIELDS``.

.. class:: CaseInsensitiveUsernameFieldCreationForm

    This is the same form as ``UserCreationForm``, but with an added method, ``clean_username``
    which lowercases the username before saving. It is recommended that you use this form if you
    choose to use either the
    :class:`~authtools.backends.CaseInsensitiveUsernameFieldModelBackend` authentication backend
    class.

    .. note::

        This form is also available sa CaseInsensitiveEmailUserCreationForm for
        backwards compatibility.

.. class:: FriendlyPasswordResetForm

    Basically the same as
    :class:`django:django.contrib.auth.forms.PasswordResetForm`, but checks the
    email address against the database and gives a friendly error message.

    .. warning::

        This form leaks user email addresses.

It also provides a Widget class.

.. class:: BetterReadOnlyPasswordHashWidget

    This is basically the same as django's ``ReadOnlyPasswordHashWidget``, but
    it provides a less intimidating user interface.  Whereas django's Widget
    displays the password hash with it's salt,
    :class:`BetterReadOnlyPasswordHashWidget` simply presents a string of
    asterisks.
