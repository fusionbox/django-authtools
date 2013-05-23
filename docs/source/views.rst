Views
=====

.. currentmodule:: authuser.views

django-authuser provides the following class-based views, intended to be
*mostly* drop-in replacements for their :ref:`built-in
<django:built-in-auth-views>` counterparts.

.. note::

    The view functions in Django were wrapped in decorators.  The classed-based
    views provided by django-authuser have the same decorators applied to their
    view functions. Any subclasses of these views will also have the same
    decorators applied.

.. class:: LoginView
    
    The view function :func:`authuser.views.login` replaces
    :func:`django:django.contrib.auth.views.login`.

    .. attribute:: disallow_authenticated

        When ``True``, authenticated users will be automatically redirected to
        the ``success_url`` when visiting this view.  Defaults to ``True``.

.. class:: LogoutView

    The view function :func:`authuser.views.logout` replaces
    :func:`django:django.contrib.auth.views.logout`.

    The ``next_page`` parameter present in the built-in function has been
    removed. Use :class:`LogoutRedirectView` to redirect after logging out.


.. class:: LogoutRedirectView

    The view function :func:`authuser.views.logout_then_login` replaces
    :func:`django:django.contrib.auth.views.logout_then_login`.

    .. attribute:: url

        The URL to redirect to after logging in.  This replaces the ``login_url``
        parameter present in the built-in function.

        For the :func:`logout_then_login` this is default to
        :django:setting:`LOGIN_REDIRECT_URL`.

.. class:: PasswordChangeView

    The view function :func:`authuser.views.password_change` replaces
    :func:`django:django.contrib.auth.views.password_change`.

    .. attribute:: success_url

        This replaces the ``post_change_redirect`` parameter present in the
        built-in function.  Defaults to the 'password_change_done' view.

.. class:: PasswordChangeDoneView

    The view function :func:`authuser.views.password_change_done` replaces
    :func:`django:django.contrib.auth.views.password_change_done`.

.. class:: PasswordResetView

    The view function :func:`authuser.views.password_reset` replaces
    :func:`django:django.contrib.auth.views.password_reset`.

    .. attribute:: success_url

        The pages which the user should be redirected to after requesting a
        password reset.  This replaces the  ``next_page`` parameter present in
        the built-in function. Defaults to the 'password_reset_done' view.

    .. attribute:: form_class

        The form class to present the user.  This replaces the
        ``password_reset_form`` parameter present in the built-in function.


.. class:: PasswordResetDoneView

    The view function :func:`authuser.views.password_reset_done` replaces
    :func:`django:django.contrib.auth.views.password_reset_done`.

.. class:: PasswordResetConfirmView

    The view function :func:`authuser.views.password_reset_confirm` replaces
    :func:`django:django.contrib.auth.views.password_reset_confirm`.

    .. attribute:: success_url

        Where to redirect the user after resetting their password.  This
        replaces the ``post_reset_redirect`` parameter present in the built-in
        function.

    .. attribute:: form_class

        The form class to present the user when resetting their password.  The
        form class must provide a ``save`` method like in the
        :class:`django:django.contrib.auth.forms.SetPasswordForm`  This
        replaces the ``set_password_form`` parameter present in the built-in
        function. Default is
        :class:`django:django.contrib.auth.forms.SetPasswordForm`.

.. class:: PasswordResetConfirmAndLoginView

    Available in the view function
    :func:`authuser.views.password_reset_confirm_and_login`.
    
    This is like :class:`PasswordResetConfirmView`, but also logs the user in
    after resetting their password.  By default, it will redirect the user to
    the :django:setting:`LOGIN_REDIRECT_URL`.

.. class:: PasswordResetCompleteView

    The view function :func:`authuser.views.password_reset_complete` replaces
    :func:`django:django.contrib.auth.views.password_reset_complete`.
