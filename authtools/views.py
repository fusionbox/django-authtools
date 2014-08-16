"""
Mostly equivalent to the views from django.contrib.auth.views, but
implemented as class-based views.
"""
from __future__ import unicode_literals

from django.conf import settings
from django.contrib.auth import get_user_model, REDIRECT_FIELD_NAME
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import (AuthenticationForm, SetPasswordForm,
                                       PasswordChangeForm, PasswordResetForm)
from django.contrib.auth.tokens import default_token_generator
from django.contrib import auth
from django.contrib.sites.models import get_current_site
from django.core.urlresolvers import reverse_lazy
from django.shortcuts import redirect, resolve_url
from django.utils.functional import lazy
from django.utils.http import base36_to_int, is_safe_url
from django.utils import six
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import FormView, TemplateView, RedirectView

from authtools.forms import FriendlyPasswordResetForm


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
        if self.redirect_field_name in self.request.REQUEST:
            redirect_to = self.request.REQUEST[self.redirect_field_name]
            if is_safe_url(redirect_to, host=self.request.get_host()):
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


class LoginView(AuthDecoratorsMixin, WithCurrentSiteMixin, WithNextUrlMixin, FormView):
    form_class = AuthenticationForm
    template_name = 'registration/login.html'
    disallow_authenticated = True
    success_url = resolve_url_lazy(settings.LOGIN_REDIRECT_URL)

    def dispatch(self, *args, **kwargs):
        if self.disallow_authenticated and self.request.user.is_authenticated():
            return redirect(self.get_success_url())
        return super(LoginView, self).dispatch(*args, **kwargs)

    def form_valid(self, form):
        auth.login(self.request, form.get_user())
        return super(LoginView, self).form_valid(form)

    def get_context_data(self, **kwargs):
        kwargs = super(LoginView, self).get_context_data(**kwargs)
        kwargs.update({
            self.redirect_field_name: self.request.REQUEST.get(
                self.redirect_field_name, '',
            ),
        })
        return kwargs

login = LoginView.as_view()


class LogoutView(NeverCacheMixin, WithCurrentSiteMixin, WithNextUrlMixin, TemplateView, RedirectView):
    template_name = 'registration/logged_out.html'
    permanent = False

    def get(self, *args, **kwargs):
        auth.logout(self.request)
        # If we have a url to redirect to, do it. Otherwise render the logged-out template.
        if self.get_redirect_url(**kwargs):
            return RedirectView.get(self, *args, **kwargs)
        else:
            return TemplateView.get(self, *args, **kwargs)

logout = LogoutView.as_view()
logout_then_login = LogoutView.as_view(
    url=reverse_lazy('login')
)


class PasswordChangeView(LoginRequiredMixin, AuthDecoratorsMixin, FormView):
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
        return super(PasswordChangeView, self).form_valid(form)

password_change = PasswordChangeView.as_view()


class PasswordChangeDoneView(LoginRequiredMixin, TemplateView):
    template_name = 'registration/password_change_done.html'

password_change_done = PasswordChangeDoneView.as_view()


# 4 views for password reset:
# - password_reset sends the mail
# - password_reset_done shows a success message for the above
# - password_reset_confirm checks the link the user clicked and
#   prompts for a new password
# - password_reset_complete shows a success message for the above


class PasswordResetView(CsrfProtectMixin, FormView):
    template_name = 'registration/password_reset_form.html'
    token_generator = default_token_generator
    success_url = reverse_lazy('password_reset_done')
    domain_override = None
    subject_template_name = 'registration/password_reset_subject.txt'
    email_template_name = 'registration/password_reset_email.html'
    from_email = None
    form_class = PasswordResetForm

    def form_valid(self, form):
        form.save(
            domain_override=self.domain_override,
            subject_template_name=self.subject_template_name,
            email_template_name=self.email_template_name,
            token_generator=self.token_generator,
            from_email=self.from_email,
            request=self.request,
        )
        return super(PasswordResetView, self).form_valid(form)

password_reset = PasswordResetView.as_view()
friendly_password_reset = PasswordResetView.as_view(
    form_class=FriendlyPasswordResetForm
)


class PasswordResetDoneView(TemplateView):
    template_name = 'registration/password_reset_done.html'

password_reset_done = PasswordResetDoneView.as_view()


class PasswordResetConfirmView(AuthDecoratorsMixin, FormView):
    template_name = 'registration/password_reset_confirm.html'
    token_generator = default_token_generator
    form_class = SetPasswordForm
    success_url = reverse_lazy('password_reset_complete')

    def dispatch(self, *args, **kwargs):
        assert self.kwargs.get('token') is not None
        self.user = self.get_user()
        return super(PasswordResetConfirmView, self).dispatch(*args, **kwargs)

    def get_queryset(self):
        return User._default_manager.all()

    def get_user(self):
        # django 1.5 uses uidb36, django 1.6 uses uidb64
        uidb36 = self.kwargs.get('uidb36')
        uidb64 = self.kwargs.get('uidb64')
        assert bool(uidb36) ^ bool(uidb64)
        try:
            if uidb36:
                uid = base36_to_int(uidb36)
            else:
                # urlsafe_base64_decode is not available in django 1.5
                from django.utils.http import urlsafe_base64_decode
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
        if self.valid_link():
            kwargs['validlink'] = True
        else:
            kwargs['validlink'] = False
            kwargs['form'] = None
        return kwargs

    def form_valid(self, form):
        if not self.valid_link():
            return self.form_invalid(form)
        self.save_form(form)
        return super(PasswordResetConfirmView, self).form_valid(form)

    def save_form(self, form):
        return form.save()


password_reset_confirm = PasswordResetConfirmView.as_view()

# Django 1.6 added this as a temporary shim, see #14881. Since our view
# works with base 36 or base 64, we can use the same view for both.
password_reset_confirm_uidb36 = PasswordResetConfirmView.as_view()


class PasswordResetConfirmAndLoginView(PasswordResetConfirmView):
    success_url = resolve_url_lazy(settings.LOGIN_REDIRECT_URL)

    def save_form(self, form):
        ret = super(PasswordResetConfirmAndLoginView, self).save_form(form)
        user = auth.authenticate(username=self.user.get_username(),
                                 password=form.cleaned_data['new_password1'])
        auth.login(self.request, user)
        return ret

password_reset_confirm_and_login = PasswordResetConfirmAndLoginView.as_view()


class PasswordResetCompleteView(TemplateView):
    template_name = 'registration/password_reset_complete.html'
    login_url = settings.LOGIN_URL

    def get_login_url(self):
        return resolve_url(self.login_url)

    def get_context_data(self, **kwargs):
        kwargs = super(PasswordResetCompleteView, self).get_context_data(**kwargs)
        kwargs['login_url'] = self.get_login_url()
        return kwargs

password_reset_complete = PasswordResetCompleteView.as_view()
