Admin
=====

.. currentmodule:: authtools.admin

django-authtools provides a couple of Admin classes. The default one is
:class:`NamedUserAdmin`, which provides an admin similar to
django.contrib.auth. If you are not using the
:class:`~authtools.models.AbstractNamedUser`, you might want the
:class:`UserAdmin` instead.

If you are using your own user model, authtools won't register an Admin class to
avoid problems. If you define ``REQUIRED_FIELDS`` on your custom model, authtools
will add those to the first fieldset.


.. class:: NamedUserAdmin

    This is the default Admin that is used if you use
    :class:`authtools.models.User` as you ``AUTH_USER_MODEL``. Provides an admin
    for the default :class:`authtools.models.User` model. It includes the
    default Permissions and Important Date sections.

.. class:: UserAdmin

    Provides a generic admin class for any User model.  It behaves as similarly
    to the built-in UserAdmin class as possible.

.. class:: StrippedUserAdmin

    Provides a simpler view on the UserAdmin, it doesn't include the Permission
    filters or the Important Dates section.


.. class:: StrippedNamedUserAdmin

    Same as StrippedUserAdmin, but for a User model that has a ``name`` field.
