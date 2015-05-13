CHANGES
=======

1.3.0 (unreleased)
------------------

- Added Django 1.7 compatibility (Antoine Catton, Rocky Meza, #35)
- **Backwards Incompatible:** Can't pass the ``next`` URL as a POST parameter
  - ``next`` should be only passed in the querystring (as a GET parameter)

  If your ``login.html`` template looks like this:

  .. code:: html

    <form method="post" action="{% url 'login' %}">
        <input type="hidden" name="next" value="{{ next }}">
        <label>Login: <input type="text" name="login"></label>
        <!-- ... -->

  You should replace it with:

  .. code:: html
    <form method="post">
        <label>Login: <input type="text" name="login"></label>
        <!-- ... -->

  This works because the current URL of the page already contains ``next`` in its querystring.

- **Backwards Incompatible:** ``LoginView.disallow_authenticated`` was changed to ``LoginView.allow_authenticated``

  If you were using ``disallow_authenticated=True`` anywhere and want to keep that behavior, you will have to change it to
  `'allow_authenticated=False``.

- **Backwards Incompatible:** ``LoginView.allow_authenticated`` is ``True`` by default (which is the default behavior in Django)

1.2.0 (2015-04-02)
------------------

- Nothing changed yet.


1.1.0 (2015-02-24)
------------------

  - PasswordChangeView now handles a ``next`` URL parameter (#24)

1.0.0 (released August 16, 2014)
--------------------------------

  - Add friendly_password_reset view and FriendlyPasswordResetForm (Antoine Catton, #18)
  - **Bugfix** Allow LOGIN_REDIRECT_URL to be unicode (Alan Johnson, Gavin Wahl, Rocky Meza, #13)
  - **Backwards Incompatible** Dropped support for Python 3.2

0.2.2 (released July 21, 2014)
------------------------------

  - Update safe urls in tests
  - Give the ability to restrain which users can reset their password
  - Add send_mail to AbstractEmailUser. (Jorge C. Leitão)


0.2.1
-----

  - Bugfix: UserAdmin was expecting a User with a `name` field.

0.2.0
-----

  - Django 1.6 support.

    Django 1.6 `broke backwards compatibility
    <https://docs.djangoproject.com/en/dev/releases/1.6/#django-contrib-auth-password-reset-uses-base-64-encoding-of-user-pk>`_
    of the ``password_reset_confirm`` view. Be sure to update any references to
    this URL. Rather than using a separate view for each encoding, authtools uses
    :class:`a single view <authtools.views.PasswordResetConfirmView>` that works
    with both.

  - Bugfix: if LOGIN_URL was a URL name, it wasn't being reversed in the
    PasswordResetConfirmView.

0.1.2 (released July 01, 2013)
------------------------------

  - Use ``prefetch_related`` in the :class:`~authtools.forms.UserChangeForm`
    to avoid doing hundreds of ``ContentType`` queries. The form from
    Django has the same feature, it wasn't copied over correctly in our
    original form.

0.1.1 (released May 30, 2013)
-----------------------------

* some bugfixes:

  - Call :meth:`UserManager.normalize_email` on an instance, not a class.
  - :class:`~authtools.models.User` should inherit its parent's ``Meta``.

0.1.0 (released May 28, 2013)
-----------------------------

- django-authtools
