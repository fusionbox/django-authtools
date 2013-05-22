from django.conf import settings
from django.contrib.auth import logout as auth_logout, login as auth_login, get_user_model, REDIRECT_FIELD_NAME
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm, SetPasswordForm, PasswordChangeForm
from django.contrib.auth.hashers import UNUSABLE_PASSWORD
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.models import get_current_site
from django.core.urlresolvers import reverse_lazy
from django.http import Http404
from django.shortcuts import redirect
from django.utils.http import base36_to_int, int_to_base36, is_safe_url
from django.utils.translation import ugettext_lazy as _
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import FormView, TemplateView
from django.utils.functional import cached_property

User = get_user_model()


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

    def get_success_url(self):
        if self.redirect_field_name in self.request.REQUEST:
            redirect_to = self.request.REQUEST[self.redirect_field_name]
            if is_safe_url(redirect_to, host=self.request.get_host()):
                return redirect_to
        return super(WithNextUrlMixin, self).get_success_url()


class LoginView(WithCurrentSiteMixin, WithNextUrlMixin, FormView):
    form_class = AuthenticationForm
    template_name = 'registration/login.html'
    disallow_authenticated = True
    success_url = settings.LOGIN_REDIRECT_URL

    def dispatch(self, *args, **kwargs):
        if self.disallow_authenticated and self.request.user.is_authenticated():
            return redirect(self.get_success_url())
        return super(LoginView, self).dispatch(*args, **kwargs)

    def form_valid(self, form):
        auth_login(self.request, form.get_user())
        return super(LoginView, self).form_valid(form)

    def get_context_data(self, **kwargs):
        kwargs = super(LoginView, self).get_context_data(**kwargs)
        kwargs.update({
            self.redirect_field_name: self.request.REQUEST.get(
                self.redirect_field_name, '',
            ),
        })
        return kwargs

login = sensitive_post_parameters()(csrf_protect(
    never_cache(LoginView.as_view()),
))


class LogoutView(WithCurrentSiteMixin, WithNextUrlMixin, TemplateView):
    template_name = 'registration/logged_out.html'

    def get(self, *args, **kwargs):
        auth_logout(self.request)

        redirect_to = self.get_success_url()
        if redirect_to:
            return redirect(redirect_to)

        return super(LogoutView, self).get(*args, **kwargs)

    def get_context_data(self, **kwargs):
        kwargs = super(LogoutView, self).get_context_data(**kwargs)
        kwargs['title'] = _('Logged out')
        return kwargs


logout = LogoutView.as_view()


class LogoutThenLoginView(LogoutView):
    success_url = settings.LOGIN_REDIRECT_URL


logout_then_login = LogoutThenLoginView.as_view()


class PasswordChangeView(FormView):
    template_name = 'registration/password_change_form.html'
    form_class = PasswordChangeForm
    success_url = reverse_lazy('authuser.views.password_change_done')

    def get_form_kwargs(self):
        kwargs = super(PasswordChangeView, self).get_form_kwargs()
        kwargs['user'] = self.get_user()
        return kwargs

    def get_user(self):
        return self.request.user

    def form_valid(self, form):
        form.save()
        return super(PasswordChangeView, self).form_valid(form)

password_change = sensitive_post_parameters()(csrf_protect(
    login_required(PasswordChangeView.as_view()),
))


class PasswordChangeDoneView(TemplateView):
    template_name = 'registration/password_change_done.html'

password_change_done = login_required(PasswordChangeDoneView.as_view())


# 4 views for password reset:
# - password_reset sends the mail
# - password_reset_done shows a success message for the above
# - password_reset_confirm checks the link the user clicked and
#   prompts for a new password
# - password_reset_complete shows a success message for the above


class PasswordResetView(FormView):
    template_name = 'registration/password_reset_form.html'
    token_generator = default_token_generator
    success_url = reverse_lazy('authuser.views.password_reset_done')
    domain_override = None
    subject_template_name = 'registration/password_reset_subject.txt'
    email_template_name = 'registration/password_reset_email.html'
    from_email = None

    def form_valid(self, form):
        users = User.objects.filter(email__iexact=form.cleaned_data['email'])
        for user in users:
            if user.password == UNUSABLE_PASSWORD:
                continue
            self.send_password_reset_email(user)
        return super(PasswordResetView, self).form_valid(form)

    def send_password_reset_email(self, user):
        from django.core.mail import send_mail
        from django.template import loader
        if not self.domain_override:
            current_site = get_current_site(self.request)
            site_name = current_site.name
            domain = current_site.domain
        else:
            site_name = domain = self.domain_override
        c = {
            'email': user.email,
            'domain': domain,
            'site_name': site_name,
            'uid': int_to_base36(user.pk),
            'user': user,
            'token': self.token_generator.make_token(user),
            'protocol': self.request.is_secure() and 'https' or 'http',
        }
        subject = loader.render_to_string(self.subject_template_name, c)
        # Email subject *must not* contain newlines
        subject = ''.join(subject.splitlines())
        email = loader.render_to_string(self.email_template_name, c)
        send_mail(subject, email, self.from_email, [user.email])

password_reset = csrf_protect(PasswordResetView.as_view())


class PasswordResetDoneView(TemplateView):
    template_name = 'registration/password_reset_done.html'

password_reset_done = PasswordResetDoneView.as_view()


class PasswordResetConfirmView(FormView):
    template_name = 'registration/password_reset_confirm.html'
    token_generator = default_token_generator
    form_class = SetPasswordForm
    success_url = reverse_lazy('authuser.views.password_reset_complete')

    def dispatch(self, *args, **kwargs):
        if self.kwargs.get('uidb36') is None or self.kwargs.get('token') is None:
            raise Http404
        return super(PasswordResetConfirmView, self).dispatch(*args, **kwargs)

    @cached_property
    def get_user(self):
        try:
            uid_int = base36_to_int(self.kwargs.get('uidb36'))
            return User._default_manager.get(pk=uid_int)
        except (ValueError, OverflowError, User.DoesNotExist):
            return None

    def valid_link(self):
        user = self.get_user()
        return user is not None and self.token_generator.check_token(user, self.kwargs.get('token'))

    def get_form_kwargs(self):
        kwargs = super(PasswordResetConfirmView, self).get_form_kwargs()
        kwargs['user'] = self.get_user()
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
        form.save()
        return super(PasswordResetConfirmView, self).form_invalid(form)

password_reset_confirm = sensitive_post_parameters()(never_cache(
    PasswordResetConfirmView.as_view(),
))


class PasswordResetCompleteView(TemplateView):
    template_name = 'registration/password_reset_complete.html'
    login_url = settings.LOGIN_URL

    def get_login_url(self):
        return self.login_url

    def get_context_data(self, **kwargs):
        kwargs = super(PasswordResetCompleteView, self).get_context_data(**kwargs)
        kwargs['login_url'] = self.get_login_url()
        return kwargs

password_reset_complete = PasswordResetCompleteView.as_view()
