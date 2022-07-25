CHANGES
=======

2.0.0 (unreleased)
------------------
** BREAKING **

Remove views and URLs. You can now use the ones built in to Django. Removes
support for Django 1.11 and Python 2.

- Add support for Django 2.2, 3.0, 3.1, 3.2, and 4.0.
- Fix bug where request is not properly set on AuthenticationForm (#102)
- Make UserAdmin compatible with Django 2.0
  - Fixes a bug where the password change link would not format correctly
  - Fixes a bug where BetterReadOnlyPasswordWidget would not work on a view only permission
- Documentation fixes (#87, #117)
- Set DEFAULT_AUTO_FIELD to AutoField in AuthtoolsConfig (#123)
  - Silences warning and prevents new migrations when using authtools with Django >= 3.2
- Normalize email in User clean method and UserManager get_by_natural_key method (weslord #112)
  - Fixes a bug where email would not be normalized when creating a user in the admin
- Migrate from TravisCI to GitHub Actions


1.7.0 (2019-06-26)
------------------

- Fix bug when using Django 1.11 where resetting a password when already logged in
  as another user caused an error
- Remove support for Django versions below 1.11 and Python below 2.7 and 3.6


1.6.0 (2017-06-14)
------------------

- Add support for Django 1.9, 1.10, 1.11 (Jared Proffitt #82)
- Remove old conditional imports dating as far back as Django 1.5
- Update readme


1.5.0 (2016-03-26)
------------------

- Update various help_text fields to match Django 1.9 (Wenze van Klink #51, Gavin Wahl #64, Jared Proffitt #67, Ivan VenOsdel #69)
- Documentation fixes (Yuki Izumi #52, Pi Delport #60, Germán Larraín #65)
- Made case-insensitive tooling work with more than just USERNAME_FIELD='username' (Jared Proffitt, Rocky Meza #72, #73)


1.4.0 (2015-11-02)
------------------

- Dropped Django 1.7 compatibility (Antoine Catton)
- Add Django 1.8 compatibility (Antoine Catton, Gavin Wahl, #56)
- **Backwards Incompatible:** Remove 1.6 URLs (Antoine Catton)
- **Backwards Incompatible:** Remove view functions

1.3.0 (unreleased)
------------------

- Added Django 1.7 compatibility (Antoine Catton, Rocky Meza, #35)
- ``LoginView.disallow_authenticated`` was changed to ``LoginView.allow_authenticated``
- ``LoginView.disallow_authenticated`` was deprecated.
- **Backwards Incompatible:** ``LoginView.allow_authenticated`` is now ``True``
  by default (which is the default behavior in Django)
- Create migrations for authtools.

  If updating from an older authtools, these migrations must be run on your apps::

    $ python manage.py migrate --fake authtools 0001_initial

    $ python manage.py migrate


1.2.0 (2015-04-02)
------------------

- Add CaseInsensitiveEmailUserCreationForm for creating users with lowercased email address
  usernames (Bradley Gordon, #31, #11)
- Add CaseInsensitiveEmailBackendMixin, CaseInsensitiveEmailModelBackend for authenticating
  case-insensitive email address usernames (Bradley Gordon, #31, #11)
- Add tox support for test running (Piper Merriam, #25)


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
  `a single view
  <https://django-authtools.readthedocs.org/en/latest/views.html#authtools.views.PasswordResetConfirmView>`_
  that works with both.

- Bugfix: if LOGIN_URL was a URL name, it wasn't being reversed in the
  PasswordResetConfirmView.

0.1.2 (released July 01, 2013)
------------------------------

- Use ``prefetch_related`` in the
  `UserChangeForm <https://django-authtools.readthedocs.org/en/latest/forms.html#authtools.forms.UserChangeForm>`_
  to avoid doing hundreds of ``ContentType`` queries. The form from
  Django has the same feature, it wasn't copied over correctly in our
  original form.

0.1.1 (released May 30, 2013)
-----------------------------

* some bugfixes:

- Call ``UserManager.normalize_email`` on an instance, not a class.
- ``authtools.models.User`` should inherit its parent's ``Meta``.

0.1.0 (released May 28, 2013)
-----------------------------

- django-authtools
