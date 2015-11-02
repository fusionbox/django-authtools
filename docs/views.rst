Views
=====

.. currentmodule:: authtools.views

django-authtools provides the following class-based views, intended to be
*mostly* drop-in replacements for their :ref:`built-in
<django:built-in-auth-views>` counterparts.

In addition to the built-in views, there is a new
:class:`PasswordResetConfirmAndLoginView` that logs in the user and redirects
them after they reset their password.

.. note::

    The view functions in Django were wrapped in decorators.  The classed-based
    views provided by django-authtools have the same decorators applied to their
    view functions. Any subclasses of these views will also have the same
    decorators applied.

.. class:: LoginView
    
    The view function :func:`authtools.views.login` replaces
    :func:`django:django.contrib.auth.views.login`.

    .. attribute:: disallow_authenticated

        When ``True``, authenticated users will be automatically redirected to
        the ``success_url`` when visiting this view.  Defaults to ``True``.

.. class:: LogoutView

    The view functions :func:`authtools.views.logout` and
    :func:`authtools.views.logout_then_login` replace
    :func:`django:django.contrib.auth.views.logout`
    :func:`django:django.contrib.auth.views.logout_then_login` respectively.

    .. attribute:: url

        The URL to redirect to after logging in.  This replaces the ``login_url``
        parameter present in the built-in function.

        For the :func:`logout_then_login` this is default to
        :django:setting:`LOGIN_REDIRECT_URL`.

    .. attribute:: template_name

        If :attr:`url` is ``None`` and there is no ``next`` parameter,
        :class:`LoginView` will act like a TemplateView and display a template.

.. class:: PasswordChangeView

    The view function :func:`authtools.views.password_change` replaces
    :func:`django:django.contrib.auth.views.password_change`.

    .. attribute:: success_url

        This replaces the ``post_change_redirect`` parameter present in the
        built-in function.  Uses the ``next`` URL parameter or defaults to the
        'password_change_done' view.

.. class:: PasswordChangeDoneView

    The view function :func:`authtools.views.password_change_done` replaces
    :func:`django:django.contrib.auth.views.password_change_done`.

.. class:: PasswordResetView

    The view function :func:`authtools.views.password_reset` replaces
    :func:`django:django.contrib.auth.views.password_reset`.

    .. attribute:: success_url

        The pages which the user should be redirected to after requesting a
        password reset.  This replaces the  ``next_page`` parameter present in
        the built-in function. Defaults to the 'password_reset_done' view.

    .. attribute:: form_class

        The form class to present the user.  This replaces the
        ``password_reset_form`` parameter present in the built-in function.

    Django 1.6 `removed the email check from this view
    <https://code.djangoproject.com/ticket/19758>`_ in order to avoid
    leaking user email addresses.

    In some cases, this can worsen user experience without providing any
    extra security. For example, if email addresses are unique, then the
    registration form will be leaking email addresses.

    If you're in this case, and you wish to improve usability of this view
    informing the user if they did any typo, you can do::

        # yourproject/urls.py
        urlpatterns += patterns( # ...
            # ...
            url('^auth/password_reset/$',
                PasswordResetView.as_view(FriendlyPasswordResetForm),
                name='password_reset'),
            url('^auth/', include('authtools.urls'),
            # ...
        )

.. class:: PasswordResetDoneView

    The view function :func:`authtools.views.password_reset_done` replaces
    :func:`django:django.contrib.auth.views.password_reset_done`.

.. class:: PasswordResetConfirmView

    The view function :func:`authtools.views.password_reset_confirm` replaces
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

    .. note::

      `Django 1.6 changed this view
      <https://docs.djangoproject.com/en/dev/releases/1.6/#django-contrib-auth-password-reset-uses-base-64-encoding-of-user-pk>`_
      to support base-64 encoding the user's pk. Django provides a different
      view for each type of encoding, but our view works with both, so we only
      have a single view.

      This was a backwards-incompatible change in Django, so be sure to update
      your urlpatterns and anywhere you reverse the ``password_reset_confirm``
      URL (like the password reset email template,
      ``registration/password_reset_email.html``).

.. class:: PasswordResetConfirmAndLoginView

    Available as the view function
    :func:`authtools.views.password_reset_confirm_and_login`.
    
    This is like :class:`PasswordResetConfirmView`, but also logs the user in
    after resetting their password.  By default, it will redirect the user to
    the :django:setting:`LOGIN_REDIRECT_URL`.

    If you wanted to use this view, you could have a url config that looks like::

        urlpatterns = patterns('',
            url('^reset/(?P<uidb36>[0-9A-Za-z]{1,13})-(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
                'authtools.views.password_reset_confirm_and_login', name='password_reset_confirm'),
            url('^', include('authtools.urls')),
        )

    .. note::

      In Django 1.6, the ``uidb36`` kwarg was changed to ``uidb64``, so your
      url will look like::

          url(r'^reset/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
              'authtools.views.password_reset_confirm_and_login',
              name='password_reset_confirm'),

      Like :class:`PasswordResetConfirmView`, this view supports both ``uid36``
      and ``uidb64``.


.. class:: PasswordResetCompleteView

    The view function :func:`authtools.views.password_reset_complete` replaces
    :func:`django:django.contrib.auth.views.password_reset_complete`.
