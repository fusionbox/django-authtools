CHANGES
=======

0.2.2 (released July 21, 2014)
-----------------------------

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
