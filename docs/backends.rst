Authentication Backends
=====

.. currentmodule:: authtools.backends

django-authtools provides two authorization backend classes. These backends offer more customization
for how your :class:`authtool.models.User` class is authenticated.

.. class:: CaseInsensitiveEmailBackendMixin

    This mixin simply calls the ``authenticate`` method of its superclass after lowercasing the
    provided username. This superclass should be a user-defined or Django-provided authentication
    backend, such as ``django.contrib.auth.backends.ModelBackend``.

    .. warning:
        Use of this mixin presupposes that all usernames are stored in their lowercase form, and
        that there is no way to have usernames differing only in case. If usernames can differ in
        case, this authentication backend mixin could cause errors in user authentication.

.. class:: CaseInsensitiveEmailModelBackend
    A subclass of the ``CaseInsentiveEmailBackendMixin`` with
    ``django.contrib.auth.backends.ModelBackend`` as its chosen authentication backend superclass.

