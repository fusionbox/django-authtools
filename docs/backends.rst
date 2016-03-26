Authentication Backends
=======================

.. currentmodule:: authtools.backends

django-authtools provides two authentication backend classes. These backends offer more customization
for authentication.

.. class:: CaseInsensitiveUsernameFieldModelBackend

    Enables case-insensitive logins for the User model. It works by simply lowercasing usernames
    before trying to authenticate.

    There is also a :class:`CaseInsensitiveUsernameFieldBackendMixin` if you need more flexibility.

    To use this backend class, add it to your settings:

    .. code-block:: python

        # settings.py
        AUTHENTICATION_BACKENDS = [
            'authtools.backends.CaseInsensitiveUsernameFieldModelBackend',
        ]

    .. warning::

        Use of this mixin assumes that all usernames are stored in their lowercase form, and
        that there is no way to have usernames differing only in case. If usernames can differ in
        case, this authentication backend mixin could cause errors in user authentication. It is
        advised that you use this mixin in conjuction with the
        :class:`~authtools.forms.CaseInsensitiveUsernameFieldCreationForm` form.

.. class:: CaseInsensitiveUsernameFieldBackendMixin

    Mixin enabling case-insensitive logins.
