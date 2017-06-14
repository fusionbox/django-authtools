"""
Mostly equivalent to the views from django.contrib.auth.views, but
implemented as class-based views.
"""
from __future__ import unicode_literals
import warnings

from django.conf import settings
from django.contrib.auth import get_user_model, REDIRECT_FIELD_NAME, login as auth_login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import (SetPasswordForm,
                                       PasswordChangeForm, PasswordResetForm)
from django.contrib.auth.tokens import default_token_generator
from django.contrib import auth
from django.http import HttpResponseRedirect

from django.contrib.sites.shortcuts import get_current_site

try:
    # django >= 1.10
    from django.urls import reverse_lazy
except ImportError:
    # django < 1.10
    from django.core.urlresolvers import reverse_lazy

try:
    from django.contrib.auth.views import INTERNAL_RESET_URL_TOKEN, INTERNAL_RESET_SESSION_TOKEN
except ImportError:
    INTERNAL_RESET_URL_TOKEN = None
    INTERNAL_RESET_SESSION_TOKEN = None

try:
    # this is used in django > 1.11
    from django.contrib.auth.views import SuccessURLAllowedHostsMixin
except ImportError:
    class SuccessURLAllowedHostsMixin(object):
        # skip since this was not available before django 1.11
        pass

from django.contrib.auth import update_session_auth_hash

from django.shortcuts import redirect, resolve_url
from django.utils.functional import lazy
from django.utils.http import base36_to_int, is_safe_url, urlsafe_base64_decode
from django.utils import six
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import FormView, TemplateView, RedirectView
from django import VERSION as DJANGO_VERSION

from .forms import AuthenticationForm

User = get_user_model()


def _safe_resolve_url(url):
    """
    Previously, resolve_url_lazy would fail if the url was a unicode object.
    See <https://github.com/fusionbox/django-authtools/issues/13> for more
    information.

    Thanks to GitHub user alanwj for pointing out the problem and providing
    this solution.
    """
    return six.text_type(resolve_url(url))

resolve_url_lazy = lazy(_safe_resolve_url, six.text_type)


class WithCurrentSiteMixin(object):
    def get_current_site(self):
        return get_current_site(self.request)

    def get_context_data(self, **kwargs):
        kwargs = super(WithCurrentSiteMixin, self).get_context_data(**kwargs)
        current_site = self.get_current_site()
        kwargs.update({
            'site': current_site,
            'site_name': current_site.name,
        })
        return kwargs


class WithNextUrlMixin(object):
    redirect_field_name = REDIRECT_FIELD_NAME
    success_url = None

    def get_next_url(self):
        request = self.request
        redirect_to = request.POST.get(self.redirect_field_name,
                                       request.GET.get(self.redirect_field_name, ''))
        if not redirect_to:
            return

        host = self.request.get_host()

        try:
            # django >= 1.11 changed host arg to allowed_hosts list arg
            allowed_hosts = [host]

            try:
                allowed_hosts += self.get_success_url_allowed_hosts()
            except AttributeError:
                pass

            url_is_safe = is_safe_url(
                redirect_to,
                allowed_hosts=allowed_hosts,
                require_https=self.request.is_secure()
            )

        except TypeError:
            # django < 1.11
            url_is_safe = is_safe_url(redirect_to, host=host)

        if url_is_safe:
            return redirect_to

    # This mixin can be mixed with FormViews and RedirectViews. They
    # each use a different method to get the URL to redirect to, so we
    # need to provide both methods.
    def get_success_url(self):
        return self.get_next_url() or super(WithNextUrlMixin, self).get_success_url()

    def get_redirect_url(self, **kwargs):
        return self.get_next_url() or super(WithNextUrlMixin, self).get_redirect_url(**kwargs)


def DecoratorMixin(decorator):
    """
    Converts a decorator written for a function view into a mixin for a
    class-based view.

    ::

        LoginRequiredMixin = DecoratorMixin(login_required)

        class MyView(LoginRequiredMixin):
            pass

        class SomeView(DecoratorMixin(some_decorator),
                       DecoratorMixin(something_else)):
            pass

    """

    class Mixin(object):
        __doc__ = decorator.__doc__

        @classmethod
        def as_view(cls, *args, **kwargs):
            view = super(Mixin, cls).as_view(*args, **kwargs)
            return decorator(view)

    Mixin.__name__ = str('DecoratorMixin(%s)' % decorator.__name__)
    return Mixin


NeverCacheMixin = DecoratorMixin(never_cache)
CsrfProtectMixin = DecoratorMixin(csrf_protect)
LoginRequiredMixin = DecoratorMixin(login_required)
SensitivePostParametersMixin = DecoratorMixin(
    sensitive_post_parameters('password', 'old_password', 'password1',
                              'password2', 'new_password1', 'new_password2')
)

class AuthDecoratorsMixin(NeverCacheMixin, CsrfProtectMixin, SensitivePostParametersMixin):
    pass


class LoginView(AuthDecoratorsMixin, SuccessURLAllowedHostsMixin,
                WithCurrentSiteMixin, WithNextUrlMixin, FormView):
    form_class = AuthenticationForm
    authentication_form = None
    template_name = 'registration/login.html'
    allow_authenticated = True
    success_url = resolve_url_lazy(settings.LOGIN_REDIRECT_URL)

    # BBB: This is deprecated (See LoginView.get_allow_authenticated)
    disallow_authenticated = None

    def get_allow_authenticated(self):
        if self.disallow_authenticated is not None:
            warnings.warn("disallow_authenticated is deprecated. Please use allow_authenticated",
                          DeprecationWarning)
            return not self.disallow_authenticated
        else:
            return self.allow_authenticated

    def dispatch(self, *args, **kwargs):
        allow_authenticated = self.get_allow_authenticated()
        if not allow_authenticated and self.request.user.is_authenticated():
            return redirect(self.get_success_url())
        return super(LoginView, self).dispatch(*args, **kwargs)

    def get_form_class(self):
        return self.authentication_form or self.form_class

    def form_valid(self, form):
        auth.login(self.request, form.get_user())
        return super(LoginView, self).form_valid(form)

    def get_context_data(self, **kwargs):
        kwargs = super(LoginView, self).get_context_data(**kwargs)
        kwargs.update({
            self.redirect_field_name: self.request.GET.get(
                self.redirect_field_name, '',
            ),
        })
        return kwargs


class LogoutView(NeverCacheMixin, SuccessURLAllowedHostsMixin, WithCurrentSiteMixin, WithNextUrlMixin, TemplateView,
                 RedirectView):
    template_name = 'registration/logged_out.html'
    permanent = False

    def get_redirect_url(self, **kwargs):
        redirect_to = super(LogoutView, self).get_redirect_url(**kwargs)

        if redirect_to:
            return redirect_to
        elif getattr(settings, 'LOGOUT_REDIRECT_URL', None) is not None:  # Setting is only available in django 1.10
            return resolve_url(settings.LOGOUT_REDIRECT_URL)
        elif self.request.POST.get(self.redirect_field_name, self.request.GET.get(self.redirect_field_name, '')):
            # we have a url, but it is not safe. Django redirects back to the same view.
            return self.request.path

    def get(self, *args, **kwargs):
        auth.logout(self.request)
        # If we have a url to redirect to, do it. Otherwise render the logged-out template.
        if self.get_redirect_url(**kwargs):
            return RedirectView.get(self, *args, **kwargs)
        else:
            return TemplateView.get(self, *args, **kwargs)


class PasswordChangeView(LoginRequiredMixin, WithNextUrlMixin, AuthDecoratorsMixin, FormView):
    template_name = 'registration/password_change_form.html'
    form_class = PasswordChangeForm
    success_url = reverse_lazy('password_change_done')

    def get_form_kwargs(self):
        kwargs = super(PasswordChangeView, self).get_form_kwargs()
        kwargs['user'] = self.get_user()
        return kwargs

    def get_user(self):
        return self.request.user

    def form_valid(self, form):
        form.save()
        # Updating the password logs out all other sessions for the user
        # except the current one if
        # django.contrib.auth.middleware.SessionAuthenticationMiddleware
        # is enabled.
        update_session_auth_hash(self.request, form.user)
        return super(PasswordChangeView, self).form_valid(form)


class PasswordChangeDoneView(LoginRequiredMixin, TemplateView):
    template_name = 'registration/password_change_done.html'


# 4 views for password reset:
# - PasswordResetView sends the mail
# - PasswordResetDoneView shows a success message for the above
# - PasswordResetConfirmView checks the link the user clicked and
#   prompts for a new password
# - PasswordResetCompleteView shows a success message for the above


class PasswordResetView(CsrfProtectMixin, FormView):
    template_name = 'registration/password_reset_form.html'
    token_generator = default_token_generator
    success_url = reverse_lazy('password_reset_done')
    domain_override = None
    subject_template_name = 'registration/password_reset_subject.txt'
    email_template_name = 'registration/password_reset_email.html'
    html_email_template_name = None
    from_email = None
    form_class = PasswordResetForm
    extra_email_context = None

    def form_valid(self, form):
        kwargs = dict(
            domain_override=self.domain_override,
            subject_template_name=self.subject_template_name,
            email_template_name=self.email_template_name,
            token_generator=self.token_generator,
            from_email=self.from_email,
            request=self.request,
            use_https=self.request.is_secure(),
            html_email_template_name=self.html_email_template_name,
        )

        if DJANGO_VERSION[:2] >= (1, 9):
            kwargs['extra_email_context'] = self.extra_email_context

        form.save(**kwargs)

        return super(PasswordResetView, self).form_valid(form)


class PasswordResetDoneView(TemplateView):
    template_name = 'registration/password_reset_done.html'


class PasswordResetConfirmView(AuthDecoratorsMixin, FormView):
    template_name = 'registration/password_reset_confirm.html'
    token_generator = default_token_generator
    form_class = SetPasswordForm
    success_url = reverse_lazy('password_reset_complete')
    post_reset_login = False
    post_reset_login_backend = None

    def dispatch(self, *args, **kwargs):
        assert self.kwargs.get('token') is not None
        self.user = self.get_user()
        self.validlink = False

        if self.user is not None:
            if INTERNAL_RESET_SESSION_TOKEN and INTERNAL_RESET_URL_TOKEN:
                # django 1.11 does this differently. Most of this is copied from django
                token = kwargs['token']
                if token == INTERNAL_RESET_URL_TOKEN:
                    session_token = self.request.session.get(INTERNAL_RESET_SESSION_TOKEN)
                    if self.token_generator.check_token(self.user, session_token):
                        # If the token is valid, display the password reset form.
                        self.validlink = True
                        return super(PasswordResetConfirmView, self).dispatch(*args, **kwargs)
                else:
                    if self.token_generator.check_token(self.user, token):
                        # Store the token in the session and redirect to the
                        # password reset form at a URL without the token. That
                        # avoids the possibility of leaking the token in the
                        # HTTP Referer header.
                        self.request.session[INTERNAL_RESET_SESSION_TOKEN] = token
                        redirect_url = self.request.path.replace(token, INTERNAL_RESET_URL_TOKEN)
                        return HttpResponseRedirect(redirect_url)
            else:
                # do the pre django 1.11 way.
                self.validlink = self.valid_link()

        return super(PasswordResetConfirmView, self).dispatch(*args, **kwargs)

    def get_queryset(self):
        return User._default_manager.all()

    def get_user(self):
        uidb64 = self.kwargs.get('uidb64')
        try:
            uid = urlsafe_base64_decode(uidb64)
            return self.get_queryset().get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return None

    def valid_link(self):
        user = self.user
        return user is not None and self.token_generator.check_token(user, self.kwargs.get('token'))

    def get_form_kwargs(self):
        kwargs = super(PasswordResetConfirmView, self).get_form_kwargs()
        kwargs['user'] = self.user
        return kwargs

    def get_context_data(self, **kwargs):
        kwargs = super(PasswordResetConfirmView, self).get_context_data(**kwargs)
        if self.validlink:
            kwargs['validlink'] = True
        else:
            kwargs['validlink'] = False
            kwargs['form'] = None
        return kwargs

    def form_valid(self, form):
        if not self.validlink:
            return self.form_invalid(form)

        user = self.save_form(form)

        if INTERNAL_RESET_SESSION_TOKEN:
            del self.request.session[INTERNAL_RESET_SESSION_TOKEN]

        if self.post_reset_login:
            auth_login(self.request, user, self.post_reset_login_backend)

        return super(PasswordResetConfirmView, self).form_valid(form)

    def save_form(self, form):
        return form.save()


class PasswordResetConfirmAndLoginView(PasswordResetConfirmView):
    success_url = resolve_url_lazy(settings.LOGIN_REDIRECT_URL)

    def save_form(self, form):
        ret = super(PasswordResetConfirmAndLoginView, self).save_form(form)
        user = auth.authenticate(username=self.user.get_username(),
                                 password=form.cleaned_data['new_password1'])
        auth.login(self.request, user)
        return ret


class PasswordResetCompleteView(TemplateView):
    template_name = 'registration/password_reset_complete.html'
    login_url = settings.LOGIN_URL

    def get_login_url(self):
        return resolve_url(self.login_url)

    def get_context_data(self, **kwargs):
        kwargs = super(PasswordResetCompleteView, self).get_context_data(**kwargs)
        kwargs['login_url'] = self.get_login_url()
        return kwargs
