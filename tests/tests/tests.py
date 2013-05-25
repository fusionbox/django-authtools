"""
We're able to borrow most of django's auth view tests.

"""

from django.core.urlresolvers import reverse
from django.contrib.sites.models import Site, RequestSite
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.utils.http import urlquote
from django.utils import unittest
from django.test import TestCase
from django.utils.encoding import force_text
from django.forms.fields import Field
from django.contrib.auth.tests.utils import skipIfCustomUser

try:
    # Django 1.6
    from django.contrib.auth.tests.test_views import (
        AuthViewNamedURLTests,
        PasswordResetTest,
        ChangePasswordTest,
        LoginTest,
        LoginURLSettings,
        LogoutTest,
    )
except ImportError:
    # Django 1.5
    from django.contrib.auth.tests.views import (
        AuthViewNamedURLTests,
        PasswordResetTest,
        ChangePasswordTest,
        LoginTest,
        LoginURLSettings,
        LogoutTest,
    )

from authuser.forms import UserCreationForm


class AuthViewNamedURLTests(AuthViewNamedURLTests):
    urls = 'authuser.urls'


class PasswordResetTest(PasswordResetTest):
    urls = 'authuser.urls'

    # these use custom, test-specific urlpatterns that we don't have
    test_admin_reset = None
    test_reset_custom_redirect = None
    test_reset_custom_redirect_named = None
    test_email_found_custom_from = None
    test_confirm_redirect_custom = None
    test_confirm_redirect_custom_named = None


class ChangePasswordTest(ChangePasswordTest):
    urls = 'authuser.urls'

    test_password_change_redirect_custom = None
    test_password_change_redirect_custom_named = None

    # the builtin test doesn't logout after the password is changed, so
    # fail_login doesn't do anything when disallow_authenticated is True.
    def test_password_change_succeeds(self):
        self.login()
        self.client.post('/password_change/', {
            'old_password': 'password',
            'new_password1': 'password1',
            'new_password2': 'password1',
        })
        self.logout()
        self.fail_login()
        self.login(password='password1')


class LoginTest(LoginTest):
    urls = 'authuser.urls'

    # the built-in tests depend on the django urlpatterns (they reverse
    # django.contrib.auth.views.login)
    def test_current_site_in_context_after_login(self):
        response = self.client.get(reverse('login'))
        self.assertEqual(response.status_code, 200)
        if Site._meta.installed:
            site = Site.objects.get_current()
            self.assertEqual(response.context['site'], site)
            self.assertEqual(response.context['site_name'], site.name)
        else:
            self.assertIsInstance(response.context['site'], RequestSite)
        self.assertTrue(isinstance(response.context['form'], AuthenticationForm),
                        'Login form is not an AuthenticationForm')

    def test_security_check(self, password='password'):
        login_url = reverse('login')

        # Those URLs should not pass the security check
        for bad_url in ('http://example.com',
                        'https://example.com',
                        'ftp://exampel.com',
                        '//example.com'):

            nasty_url = '%(url)s?%(next)s=%(bad_url)s' % {
                'url': login_url,
                'next': REDIRECT_FIELD_NAME,
                'bad_url': urlquote(bad_url),
            }
            response = self.client.post(nasty_url, {
                'username': 'testclient',
                'password': password,
            })
            self.assertEqual(response.status_code, 302)
            self.assertFalse(bad_url in response['Location'],
                             "%s should be blocked" % bad_url)

        # These URLs *should* still pass the security check
        for good_url in ('/view/?param=http://example.com',
                         '/view/?param=https://example.com',
                         '/view?param=ftp://exampel.com',
                         'view/?param=//example.com',
                         'https:///',
                         '//testserver/',
                         '/url%20with%20spaces/'):  # see ticket #12534
            safe_url = '%(url)s?%(next)s=%(good_url)s' % {
                'url': login_url,
                'next': REDIRECT_FIELD_NAME,
                'good_url': urlquote(good_url),
            }
            response = self.client.post(safe_url, {
                'username': 'testclient',
                'password': password,
            })
            self.assertEqual(response.status_code, 302)
            self.assertTrue(good_url in response['Location'],
                            "%s should be allowed" % good_url)


class LoginURLSettings(LoginURLSettings):
    urls = 'tests.urls'


class LogoutTest(LogoutTest):
    urls = 'tests.urls'

    test_logout_with_overridden_redirect_url = None
    test_logout_with_next_page_specified = None
    test_logout_with_custom_redirect_argument = None
    test_logout_with_named_redirect = None
    test_logout_with_custom_redirect_argument = None

    # the built-in tests depend on the django urlpatterns (they reverse
    # django.contrib.auth.views.login)
    def test_security_check(self, password='password'):
        logout_url = reverse('logout_then_login')

        # Those URLs should not pass the security check
        for bad_url in ('http://example.com',
                        'https://example.com',
                        'ftp://exampel.com',
                        '//example.com'):
            nasty_url = '%(url)s?%(next)s=%(bad_url)s' % {
                'url': logout_url,
                'next': REDIRECT_FIELD_NAME,
                'bad_url': urlquote(bad_url),
            }
            self.login()
            response = self.client.get(nasty_url)
            self.assertEqual(response.status_code, 302)
            self.assertFalse(bad_url in response['Location'],
                             "%s should be blocked" % bad_url)
            self.confirm_logged_out()

        # These URLs *should* still pass the security check
        for good_url in ('/view/?param=http://example.com',
                         '/view/?param=https://example.com',
                         '/view?param=ftp://exampel.com',
                         'view/?param=//example.com',
                         'https:///',
                         '//testserver/',
                         '/url%20with%20spaces/'):  # see ticket #12534
            safe_url = '%(url)s?%(next)s=%(good_url)s' % {
                'url': logout_url,
                'next': REDIRECT_FIELD_NAME,
                'good_url': urlquote(good_url),
            }
            self.login()
            response = self.client.get(safe_url)
            self.assertEqual(response.status_code, 302)
            self.assertTrue(good_url in response['Location'],
                            "%s should be allowed" % good_url)
            self.confirm_logged_out()

    # our login view doesn't accept a next param, for now
    @unittest.expectedFailure
    def test_logout_with_redirect_argument(self):
        return super(LogoutTest, self).test_logout_with_redirect_argument()


@skipIfCustomUser
class UserCreationFormTest(TestCase):
    fixtures = ['authtestdata.json']

    def test_user_already_exists(self):
        data = {
            'username': 'testclient',
            'password1': 'test123',
            'password2': 'test123',
        }
        form = UserCreationForm(data)
        self.assertFalse(form.is_valid())
        self.assertEqual(form["username"].errors, [
            force_text(form.error_messages['duplicate_username']) % {'username': 'username'}])

    def test_password_verification(self):
        # The verification password is incorrect.
        data = {
            'username': 'jsmith',
            'password1': 'test123',
            'password2': 'test',
        }
        form = UserCreationForm(data)
        self.assertFalse(form.is_valid())
        self.assertEqual(form["password2"].errors,
                         [force_text(form.error_messages['password_mismatch'])])

    def test_both_passwords(self):
        # One (or both) passwords weren't given
        data = {'username': 'jsmith'}
        form = UserCreationForm(data)
        required_error = [force_text(Field.default_error_messages['required'])]
        self.assertFalse(form.is_valid())
        self.assertEqual(form['password1'].errors, required_error)
        self.assertEqual(form['password2'].errors, required_error)

        data['password2'] = 'test123'
        form = UserCreationForm(data)
        self.assertFalse(form.is_valid())
        self.assertEqual(form['password1'].errors, required_error)
        self.assertEqual(form['password2'].errors, [])

    def test_success(self):
        # The success case.
        data = {
            'username': 'jsmith@example.com',
            'password1': 'test123',
            'password2': 'test123',
        }
        form = UserCreationForm(data)
        self.assertTrue(form.is_valid())
        u = form.save()
        self.assertEqual(repr(u), '<User: jsmith@example.com>')
