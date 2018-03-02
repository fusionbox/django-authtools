"""
We're able to borrow most of django's auth view tests.

"""
import collections
import contextlib
import itertools
import warnings

import datetime

try:
    from unittest import skipIf, skipUnless
except ImportError:  # Python < 2.7
    from django.utils.unittest import skipIf, skipUnless

from django.core import mail

try:
    # django >= 1.10
    from django.urls import reverse
except ImportError:
    # django < 1.10
    from django.core.urlresolvers import reverse

from django.contrib.auth import REDIRECT_FIELD_NAME, get_user_model, SESSION_KEY
from django.contrib.auth.forms import AuthenticationForm
from django.utils.http import urlquote
from django.test import TestCase
from django.test.client import RequestFactory
from django.test.utils import override_settings
from django.utils.encoding import force_text
from django.utils.translation import ugettext as _
from django.forms.fields import Field
from django.conf import settings
from django.http import HttpRequest
from django.middleware.csrf import CsrfViewMiddleware, get_token
from django.contrib.sessions.middleware import SessionMiddleware
from django import VERSION as DJANGO_VERSION

try:
    # django >= 1.11
    from django.contrib.auth.views import LoginView
    login_view = LoginView.as_view()
except ImportError:
    # django < 1.11
    from django.contrib.auth.views import login as login_view

from authtools.views import LoginView

from auth_tests.test_views import (
    AuthViewNamedURLTests,
    PasswordResetTest,
    ChangePasswordTest,
    LoginTest,
    LoginURLSettings,
    LogoutTest,
)

from django.contrib.sites.shortcuts import get_current_site


from authtools.admin import BASE_FIELDS
from authtools.forms import (
    UserCreationForm,
    UserChangeForm,
    FriendlyPasswordResetForm,
    CaseInsensitiveUsernameFieldCreationForm,
    CaseInsensitiveEmailUserCreationForm,
    AdminUserChangeForm)
from authtools.views import PasswordResetCompleteView, resolve_url_lazy

User = get_user_model()


def skipIfNotCustomUser(test_func):
    return skipIf(settings.AUTH_USER_MODEL == 'auth.User', 'Built-in User model in use')(test_func)


def skipIfCustomUser(test_func):
    """
    Copied from django.contrib.auth.tests.utils, This is deprecated in the future, but we still
    need it for some of our tests.
    """
    return skipIf(settings.AUTH_USER_MODEL != 'auth.User', 'Custom user model in use')(test_func)


class WarningTestMixin(object):
    @contextlib.contextmanager
    def assertWarns(self, warning_classes):
        if not isinstance(warning_classes, collections.Iterable):
            warning_classes = [warning_classes]

        with warnings.catch_warnings(record=True) as warn:
            warnings.simplefilter("always")
            yield
            assert len(warn) == len(warning_classes)
            for msg, expected_class in zip(warn, warning_classes):
                assert issubclass(msg.category, expected_class)


class EmailLoginMixin(object):
    if settings.AUTH_USER_MODEL != 'auth.User':
        if DJANGO_VERSION[:2] < (1, 9):
            if settings.AUTH_USER_MODEL == 'authtools.User':
                fixtures = ['authtoolstestdata.json']
            elif settings.AUTH_USER_MODEL == 'tests.User':
                fixtures = ['customusertestdata.json']

        def login(self, username='testclient', password='password'):
            """
            Authtools uses email addresses to login.

            Fortunately, email addresses in the fixtures are username + '@example.com'
            """
            if username == 'staff':
                username = 'staffmember@example.com'
            elif '@' not in username:
                username = username + '@example.com'
            return super(EmailLoginMixin, self).login(username, password)


class AuthViewsTestCaseDataMixin(object):
    """
    Helper base class for all the follow test cases.
    """

    if DJANGO_VERSION[:2] >= (1, 9):
        @classmethod
        def setUpTestData(cls):
            if settings.AUTH_USER_MODEL == 'auth.User':
                cls.u1 = User.objects.create(
                    password='sha1$6efc0$f93efe9fd7542f25a7be94871ea45aa95de57161',
                    last_login=datetime.datetime(2006, 12, 17, 7, 3, 31), is_superuser=False, username='testclient',
                    first_name='Test', last_name='Client', email='testclient@example.com', is_staff=False, is_active=True,
                    date_joined=datetime.datetime(2006, 12, 17, 7, 3, 31)
                )
                cls.u2 = User.objects.create(
                    password='sha1$6efc0$f93efe9fd7542f25a7be94871ea45aa95de57161',
                    last_login=datetime.datetime(2006, 12, 17, 7, 3, 31), is_superuser=False, username='inactive',
                    first_name='Inactive', last_name='User', email='testclient2@example.com', is_staff=False, is_active=False,
                    date_joined=datetime.datetime(2006, 12, 17, 7, 3, 31)
                )
                cls.u3 = User.objects.create(
                    password='sha1$6efc0$f93efe9fd7542f25a7be94871ea45aa95de57161',
                    last_login=datetime.datetime(2006, 12, 17, 7, 3, 31), is_superuser=False, username='staff',
                    first_name='Staff', last_name='Member', email='staffmember@example.com', is_staff=True, is_active=True,
                    date_joined=datetime.datetime(2006, 12, 17, 7, 3, 31)
                )
                cls.u4 = User.objects.create(
                    password='', last_login=datetime.datetime(2006, 12, 17, 7, 3, 31), is_superuser=False,
                    username='empty_password', first_name='Empty', last_name='Password', email='empty_password@example.com',
                    is_staff=False, is_active=True, date_joined=datetime.datetime(2006, 12, 17, 7, 3, 31)
                )
                cls.u5 = User.objects.create(
                    password='$', last_login=datetime.datetime(2006, 12, 17, 7, 3, 31), is_superuser=False,
                    username='unmanageable_password', first_name='Unmanageable', last_name='Password',
                    email='unmanageable_password@example.com', is_staff=False, is_active=True,
                    date_joined=datetime.datetime(2006, 12, 17, 7, 3, 31)
                )
                cls.u6 = User.objects.create(
                    password='foo$bar', last_login=datetime.datetime(2006, 12, 17, 7, 3, 31), is_superuser=False,
                    username='unknown_password', first_name='Unknown', last_name='Password',
                    email='unknown_password@example.com', is_staff=False, is_active=True,
                    date_joined=datetime.datetime(2006, 12, 17, 7, 3, 31)
                )
            else:
                cls.u1 = User.objects.create(
                    password='sha1$6efc0$f93efe9fd7542f25a7be94871ea45aa95de57161',
                    last_login=datetime.datetime(2006, 12, 17, 7, 3, 31), is_superuser=False,
                    email='testclient@example.com', is_staff=False, is_active=True,
                    date_joined=datetime.datetime(2006, 12, 17, 7, 3, 31)
                )
                cls.u2 = User.objects.create(
                    password='sha1$6efc0$f93efe9fd7542f25a7be94871ea45aa95de57161',
                    last_login=datetime.datetime(2006, 12, 17, 7, 3, 31), is_superuser=False,
                    email='testclient2@example.com', is_staff=False, is_active=False,
                    date_joined=datetime.datetime(2006, 12, 17, 7, 3, 31)
                )
                cls.u3 = User.objects.create(
                    password='sha1$6efc0$f93efe9fd7542f25a7be94871ea45aa95de57161',
                    last_login=datetime.datetime(2006, 12, 17, 7, 3, 31), is_superuser=False,
                    email='staffmember@example.com', is_staff=True, is_active=True,
                    date_joined=datetime.datetime(2006, 12, 17, 7, 3, 31)
                )
                cls.u4 = User.objects.create(
                    password='', last_login=datetime.datetime(2006, 12, 17, 7, 3, 31), is_superuser=False,
                    email='empty_password@example.com',
                    is_staff=False, is_active=True, date_joined=datetime.datetime(2006, 12, 17, 7, 3, 31)
                )
                cls.u5 = User.objects.create(
                    password='$', last_login=datetime.datetime(2006, 12, 17, 7, 3, 31), is_superuser=False,
                    email='unmanageable_password@example.com', is_staff=False, is_active=True,
                    date_joined=datetime.datetime(2006, 12, 17, 7, 3, 31)
                )
                cls.u6 = User.objects.create(
                    password='foo$bar', last_login=datetime.datetime(2006, 12, 17, 7, 3, 31), is_superuser=False,
                    email='unknown_password@example.com', is_staff=False, is_active=True,
                    date_joined=datetime.datetime(2006, 12, 17, 7, 3, 31)
                )


@override_settings(ROOT_URLCONF='authtools.urls')
class AuthViewNamedURLTests(AuthViewsTestCaseDataMixin, AuthViewNamedURLTests):
    if DJANGO_VERSION[:2] < (1, 9):
        if settings.AUTH_USER_MODEL == 'authtools.User':
            fixtures = ['authtoolstestdata.json']
        elif settings.AUTH_USER_MODEL == 'tests.User':
            fixtures = ['customusertestdata.json']


class UtilsTest(TestCase):
    def test_resolve_lazy_unicode(self):
        self.assertTrue(resolve_url_lazy(u'/'))


@override_settings(ROOT_URLCONF='tests.urls')
class PasswordResetTest(EmailLoginMixin, AuthViewsTestCaseDataMixin, PasswordResetTest):
    # these use custom, test-specific urlpatterns that we don't have
    test_admin_reset = None
    test_reset_custom_redirect = None
    test_reset_custom_redirect_named = None
    test_email_found_custom_from = None
    test_confirm_redirect_custom = None
    test_confirm_redirect_custom_named = None
    # these reference the builtin user model
    test_confirm_invalid_post = None
    test_confirm_display_user_from_form = None
    test_confirm_complete = None

    def assertFormError(self, response, error):
        """Assert that error is found in response.context['form'] errors"""
        form_errors = list(itertools.chain(*response.context['form'].errors.values()))
        self.assertIn(force_text(error), form_errors)

    # test the django 1.5 behavior
    def test_email_not_found_in_friendly_password_reset_form(self):
        "Error is raised if the provided email address isn't currently registered"
        response = self.client.get('/friendly_password_reset/')
        self.assertEqual(response.status_code, 200)
        response = self.client.post('/friendly_password_reset/',
                                    {'email': 'not_a_real_email@email.com'})
        self.assertFormError(response, FriendlyPasswordResetForm.error_messages['unknown'])
        self.assertEqual(len(mail.outbox), 0)

    def test_user_only_fetched_once(self):
        url, confirm_path = self._test_confirm_start()

        if DJANGO_VERSION[:2] >= (1, 11):
            # django 1.11 checks and adds the token to the session, so there are a few more queries
            num_queries = 9
        else:
            num_queries = 1

        with self.assertNumQueries(num_queries):
            # the confirm view is only allowed to fetch the user object a
            # single time
            self.client.get(confirm_path)

    def test_confirm_invalid_path(self):
        # django has a similar test, but it tries to test an invalid path AND
        # an invalid form at the same time. We need a test case with an invalid
        # path, but valid form.
        url, path = self._test_confirm_start()
        path = path[:-5] + ("0" * 4) + path[-1]

        self.client.post(path, {
            'new_password1': 'anewpassword',
            'new_password2': 'anewpassword',
        })
        # Check the password has not been changed
        u = User.objects.get(email='staffmember@example.com')
        self.assertTrue(not u.check_password("anewpassword"))

    def test_confirm_done(self):
        """
        Password reset complete page should be rendered with 'login_url'
        in its context.
        """
        url, path = self._test_confirm_start()
        response = self.client.post(path, {'new_password1': 'anewpassword',
                                           'new_password2': 'anewpassword'})
        self.assertEqual(response.status_code, 302)

        response = self.client.get(response['Location'])

        self.assertIn('login_url', response.context)

    def test_confirm_login_url_resolves(self):
        complete_view = PasswordResetCompleteView.as_view(login_url='login_required')
        request_factory = RequestFactory()
        response = complete_view(request_factory.get('/xxx/'))
        self.assertEqual(response.context_data['login_url'], reverse('login_required'))

        complete_view2 = PasswordResetCompleteView.as_view(login_url='/dont-change-me/')
        response = complete_view2(request_factory.get('/xxx/'))
        self.assertEqual(response.context_data['login_url'], '/dont-change-me/')

    def test_confirm_and_login(self):
        url, path = self._test_confirm_start()
        path = path.replace('reset', 'reset_and_login')
        response = self.client.post(path, {'new_password1': 'anewpassword',
                                           'new_password2': 'anewpassword'})
        self.assertEqual(response.status_code, 302)

        if 'reset_and_login' in response.url:
            # django > 1.11 redirects back with the token in the session, so we need to post again.
            response = self.client.post(response.url, {'new_password1': 'anewpassword',
                                               'new_password2': 'anewpassword'})
            self.assertEqual(response.status_code, 302)

        # verify that we're actually logged in
        response = self.client.get('/login_required/')
        self.assertEqual(response.status_code, 200)

    def test_confirm_invalid_hash(self):
        """A POST with an invalid token is rejected."""
        u = User.objects.get(email='staffmember@example.com')
        original_password = u.password
        url, path = self._test_confirm_start()
        path_parts = path.split('-')
        path_parts[-1] = ("0") * 20 + '/'
        path = '-'.join(path_parts)

        response = self.client.post(path, {
            'new_password1': 'anewpassword',
            'new_password2': 'anewpassword',
        })
        self.assertIs(response.context['validlink'], False)
        u.refresh_from_db()
        self.assertEqual(original_password, u.password)  # password hasn't changed


@override_settings(ROOT_URLCONF='authtools.urls')
class ChangePasswordTest(EmailLoginMixin, AuthViewsTestCaseDataMixin, ChangePasswordTest):

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

    def fail_login(self, password='password'):
        response = self.client.post('/login/', {
            'username': 'testclient',
            'password': password,
        })
        self.assertFormError(response, AuthenticationForm.error_messages['invalid_login'] % {
            'username': User._meta.get_field(User.USERNAME_FIELD).verbose_name
        })


# @override_settings(ROOT_URLCONF='authtools.urls')
class LoginTest(EmailLoginMixin, AuthViewsTestCaseDataMixin, LoginTest):
    # the built-in tests depend on the django urlpatterns (they reverse
    # django.contrib.auth.views.login)

    if settings.AUTH_USER_MODEL == 'auth.User':
        default_login = 'testclient'
    else:
        default_login = 'testclient@example.com'

    def test_current_site_in_context_after_login(self):
        response = self.client.get(reverse('login'))
        self.assertEqual(response.status_code, 200)
        site = get_current_site(response.request)
        self.assertEqual(response.context['site'], site)
        self.assertEqual(response.context['site_name'], site.name)
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
                'username': self.default_login,
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
                         '//testserver/',
                         '/url%20with%20spaces/'):  # see ticket #12534
            safe_url = '%(url)s?%(next)s=%(good_url)s' % {
                'url': login_url,
                'next': REDIRECT_FIELD_NAME,
                'good_url': urlquote(good_url),
            }
            response = self.client.post(safe_url, {
                'username': self.default_login,
                'password': password,
            })
            self.assertEqual(response.status_code, 302)
            self.assertTrue(good_url in response['Location'],
                            "%s should be allowed" % good_url)

    def test_login_csrf_rotate(self, login=default_login, password='password'):
        """
        Makes sure that a login rotates the currently-used CSRF token.

        This is copy-pasted from django to allow specifying the login (username).
        """
        # Do a GET to establish a CSRF token
        # TestClient isn't used here as we're testing middleware, essentially.
        req = HttpRequest()
        CsrfViewMiddleware().process_view(req, login_view, (), {})
        # get_token() triggers CSRF token inclusion in the response
        get_token(req)
        resp = login_view(req)
        resp2 = CsrfViewMiddleware().process_response(req, resp)
        csrf_cookie = resp2.cookies.get(settings.CSRF_COOKIE_NAME, None)
        token1 = csrf_cookie.coded_value

        # Prepare the POST request
        req = HttpRequest()
        req.COOKIES[settings.CSRF_COOKIE_NAME] = token1
        req.method = "POST"
        req.POST = {'username': login, 'password': password, 'csrfmiddlewaretoken': token1}

        # Use POST request to log in
        SessionMiddleware().process_request(req)
        CsrfViewMiddleware().process_view(req, login_view, (), {})
        req.META["SERVER_NAME"] = "testserver"  # Required to have redirect work in login view
        req.META["SERVER_PORT"] = 80
        resp = login_view(req)
        resp2 = CsrfViewMiddleware().process_response(req, resp)
        csrf_cookie = resp2.cookies.get(settings.CSRF_COOKIE_NAME, None)
        token2 = csrf_cookie.coded_value

        # Check the CSRF token switched
        self.assertNotEqual(token1, token2)

    def test_login_form_contains_request(self):
        # The custom authentication form for this login requires a request to
        # initialize it.
        response = self.client.post('/custom_request_auth_login/', {
            'username': self.default_login,
            'password': 'password',
        })
        # The login was successful.
        self.assertRedirects(response, settings.LOGIN_REDIRECT_URL, fetch_redirect_response=False)

    if hasattr(LoginTest, 'test_security_check_https'):
        def test_security_check_https(self):
            login_url = reverse('login')
            non_https_next_url = 'http://testserver/path'
            not_secured_url = '%(url)s?%(next)s=%(next_url)s' % {
                'url': login_url,
                'next': REDIRECT_FIELD_NAME,
                'next_url': urlquote(non_https_next_url),
            }
            post_data = {
                'username': self.default_login,
                'password': 'password',
            }
            response = self.client.post(not_secured_url, post_data, secure=True)
            self.assertEqual(response.status_code, 302)
            self.assertNotEqual(response.url, non_https_next_url)
            self.assertEqual(response.url, settings.LOGIN_REDIRECT_URL)

    # these reference the builtin user model
    test_session_key_flushed_on_login_after_password_change = None
    test_login_session_without_hash_session_key = None


class DeprecationTest(WarningTestMixin, TestCase):

    def test_disallow_authenticated_is_deprecated_on_login_view(self):
        with self.assertWarns(DeprecationWarning):
            class CustomLoginView(LoginView):
                disallow_authenticated = False

            view = CustomLoginView()
            assert view.get_allow_authenticated()

        with self.assertWarns(DeprecationWarning):

            # Simulate LoginView.as_view(disallow_authenticated=False) behavior
            view = LoginView()
            view.disallow_authenticated = False

            assert view.get_allow_authenticated()


@override_settings(ROOT_URLCONF='tests.urls')
class LoginURLSettings(AuthViewsTestCaseDataMixin, LoginURLSettings):
    if DJANGO_VERSION[:2] < (1, 9):
        if settings.AUTH_USER_MODEL == 'authtools.User':
            fixtures = ['authtoolstestdata.json']
        elif settings.AUTH_USER_MODEL == 'tests.User':
            fixtures = ['customusertestdata.json']


@override_settings(ROOT_URLCONF='tests.urls')
class LogoutTest(EmailLoginMixin, AuthViewsTestCaseDataMixin, LogoutTest):
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


class UserCreationFormTest(TestCase):
    def setUp(self):
        # in built-in UserManager, the order of arguments is:
        #     username, email, password
        # in authtools UserManager, the order of arguments is:
        #     USERNAME_FIELD, password
        User.objects.create_user('testclient@example.com', password='test123')
        self.username = User.USERNAME_FIELD

    def test_user_already_exists(self):
        # The benefit of the custom validation message is only available if the
        # messages are translated.  We won't be able to translate all the
        # strings if we don't know what the username will be ahead of time.
        data = {
            self.username: 'testclient@example.com',
            'password1': 'test123',
            'password2': 'test123',
        }
        form = UserCreationForm(data)
        self.assertFalse(form.is_valid())
        self.assertEqual(form[self.username].errors, [
            force_text(form.error_messages['duplicate_username']) % {'username': self.username}])

    def test_password_verification(self):
        # The verification password is incorrect.
        data = {
            self.username: 'jsmith',
            'password1': 'test123',
            'password2': 'test',
        }
        form = UserCreationForm(data)
        self.assertFalse(form.is_valid())
        self.assertEqual(form["password2"].errors,
                         [force_text(form.error_messages['password_mismatch'])])

    def test_both_passwords(self):
        # One (or both) passwords weren't given
        data = {self.username: 'jsmith'}
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
            self.username: 'jsmith@example.com',
            'password1': 'test123',
            'password2': 'test123',
        }

        if settings.AUTH_USER_MODEL == 'authtools.User':
            data['name'] = 'John Smith'

        form = UserCreationForm(data)
        self.assertTrue(form.is_valid())
        u = form.save()
        self.assertEqual(getattr(u, self.username), 'jsmith@example.com')
        self.assertTrue(u.check_password('test123'))
        self.assertEqual(u, User._default_manager.get_by_natural_key('jsmith@example.com'))

    def test_generated_fields_list(self):
        if settings.AUTH_USER_MODEL == 'auth.User':
            fields = ('username', 'email', 'password1', 'password2')
        elif settings.AUTH_USER_MODEL == 'authtools.User':
            fields = ('email', 'name', 'password1', 'password2')
        elif settings.AUTH_USER_MODEL == 'tests.User':
            fields = ('email', 'full_name', 'preferred_name', 'password1', 'password2')
        else:
            assert False, "I don't know your user model"

        form = UserCreationForm()
        self.assertSequenceEqual(list(form.fields.keys()), fields)


@skipIfCustomUser
@override_settings(USE_TZ=False, PASSWORD_HASHERS=('django.contrib.auth.hashers.SHA1PasswordHasher',))
class UserChangeFormTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.u1 = User.objects.create(
            password='sha1$6efc0$f93efe9fd7542f25a7be94871ea45aa95de57161',
            last_login=datetime.datetime(2006, 12, 17, 7, 3, 31), is_superuser=False, username='testclient',
            first_name='Test', last_name='Client', email='testclient@example.com', is_staff=False, is_active=True,
            date_joined=datetime.datetime(2006, 12, 17, 7, 3, 31)
        )
        # cls.u3 = User.objects.create(
        #     password='sha1$6efc0$f93efe9fd7542f25a7be94871ea45aa95de57161',
        #     last_login=datetime.datetime(2006, 12, 17, 7, 3, 31), is_superuser=False, username='staff',
        #     first_name='Staff', last_name='Member', email='staffmember@example.com', is_staff=True, is_active=True,
        #     date_joined=datetime.datetime(2006, 12, 17, 7, 3, 31)
        # )
        cls.u4 = User.objects.create(
            password='', last_login=datetime.datetime(2006, 12, 17, 7, 3, 31), is_superuser=False,
            username='empty_password', first_name='Empty', last_name='Password', email='empty_password@example.com',
            is_staff=False, is_active=True, date_joined=datetime.datetime(2006, 12, 17, 7, 3, 31)
        )
        cls.u5 = User.objects.create(
            password='$', last_login=datetime.datetime(2006, 12, 17, 7, 3, 31), is_superuser=False,
            username='unmanageable_password', first_name='Unmanageable', last_name='Password',
            email='unmanageable_password@example.com', is_staff=False, is_active=True,
            date_joined=datetime.datetime(2006, 12, 17, 7, 3, 31)
        )
        cls.u6 = User.objects.create(
            password='foo$bar', last_login=datetime.datetime(2006, 12, 17, 7, 3, 31), is_superuser=False,
            username='unknown_password', first_name='Unknown', last_name='Password',
            email='unknown_password@example.com', is_staff=False, is_active=True,
            date_joined=datetime.datetime(2006, 12, 17, 7, 3, 31)
        )

    def test_bug_14242(self):
        # A regression test, introduce by adding an optimization for the
        # UserChangeForm.

        class MyUserForm(UserChangeForm):
            def __init__(self, *args, **kwargs):
                super(MyUserForm, self).__init__(*args, **kwargs)
                self.fields['groups'].help_text = 'These groups give users different permissions'

            class Meta(UserChangeForm.Meta):
                fields = ('groups',)

        # Just check we can create it
        MyUserForm({})

    def test_unsuable_password(self):
        user = User.objects.get(username='empty_password')
        user.set_unusable_password()
        user.save()
        form = UserChangeForm(instance=user)
        self.assertIn(_("No password set."), form.as_table())

    def test_bug_17944_empty_password(self):
        user = User.objects.get(username='empty_password')
        form = UserChangeForm(instance=user)
        self.assertIn(_("No password set."), form.as_table())

    def test_bug_17944_unmanageable_password(self):
        user = User.objects.get(username='unmanageable_password')
        form = UserChangeForm(instance=user)
        self.assertIn(_("Invalid password format or unknown hashing algorithm."),
                      form.as_table())

    def test_bug_17944_unknown_password_algorithm(self):
        user = User.objects.get(username='unknown_password')
        form = UserChangeForm(instance=user)
        self.assertIn(_("Invalid password format or unknown hashing algorithm."),
                      form.as_table())

    def test_bug_19133(self):
        "The change form does not return the password value"
        # Use the form to construct the POST data
        user = User.objects.get(username='testclient')
        form_for_data = UserChangeForm(instance=user)
        post_data = form_for_data.initial

        # The password field should be readonly, so anything
        # posted here should be ignored; the form will be
        # valid, and give back the 'initial' value for the
        # password field.
        post_data['password'] = 'new password'
        form = UserChangeForm(instance=user, data=post_data)

        self.assertTrue(form.is_valid())
        self.assertEqual(form.cleaned_data['password'], 'sha1$6efc0$f93efe9fd7542f25a7be94871ea45aa95de57161')

    def test_bug_19349_bound_password_field(self):
        user = User.objects.get(username='testclient')
        form = UserChangeForm(data={}, instance=user)
        # When rendering the bound password field,
        # ReadOnlyPasswordHashWidget needs the initial
        # value to render correctly
        self.assertEqual(form.initial['password'], form['password'].value())

    def test_better_readonly_password_widget(self):
        user = User.objects.get(username='testclient')
        form = UserChangeForm(instance=user)

        self.assertIn(_('*************'), form.as_table())


@skipIfCustomUser
class AdminUserChangeFormTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.u = User.objects.create(
            password='sha1$6efc0$f93efe9fd7542f25a7be94871ea45aa95de57161',
            last_login=datetime.datetime(2006, 12, 17, 7, 3, 31), is_superuser=False, username='testclient',
            first_name='Test', last_name='Client', email='testclient@example.com', is_staff=False, is_active=True,
            date_joined=datetime.datetime(2006, 12, 17, 7, 3, 31)
        )

    def test_password_reset_link(self):
        user = User.objects.get(username='testclient')
        form = AdminUserChangeForm(data={}, instance=user)
        if DJANGO_VERSION[:2] < (1, 9):
            assert 'href="password/"' in form.fields['password'].help_text
        else:
            assert 'href="../password/"' in form.fields['password'].help_text


class UserAdminTest(TestCase):
    def test_generated_fieldsets(self):
        if settings.AUTH_USER_MODEL == 'auth.User':
            fields = ('username', 'email', 'password')
        elif settings.AUTH_USER_MODEL == 'authtools.User':
            fields = ('email', 'name', 'password')
        elif settings.AUTH_USER_MODEL == 'tests.User':
            fields = ('email', 'full_name', 'preferred_name', 'password')
        else:
            assert False, "I don't know your user model"

        self.assertSequenceEqual(BASE_FIELDS[1]['fields'], fields)


class UserManagerTest(TestCase):
    def test_create_user(self):
        u = User._default_manager.create_user(**{
            User.USERNAME_FIELD: 'newuser@example.com',
            'password': 'test123',
        })

        self.assertEqual(getattr(u, User.USERNAME_FIELD), 'newuser@example.com')
        self.assertTrue(u.check_password('test123'))
        self.assertEqual(u, User._default_manager.get_by_natural_key('newuser@example.com'))
        self.assertTrue(u.is_active)
        self.assertFalse(u.is_staff)
        self.assertFalse(u.is_superuser)

    @skipIfNotCustomUser
    def test_create_superuser(self):
        u = User._default_manager.create_superuser(**{
            User.USERNAME_FIELD: 'newuser@example.com',
            'password': 'test123',
        })

        self.assertTrue(u.is_staff)
        self.assertTrue(u.is_superuser)


class UserModelTest(TestCase):
    @skipUnless(settings.AUTH_USER_MODEL == 'authtools.User',
                         "only check authuser's ordering")
    def test_default_ordering(self):
        self.assertSequenceEqual(['name', 'email'], User._meta.ordering)

    def test_send_mail(self):
        abstract_user = User(email='foo@bar.com')
        abstract_user.email_user(subject="Subject here",
            message="This is a message", from_email="from@domain.com")
        # Test that one message has been sent.
        self.assertEqual(len(mail.outbox), 1)
        # Verify that test email contains the correct attributes:
        message = mail.outbox[0]
        self.assertEqual(message.subject, "Subject here")
        self.assertEqual(message.body, "This is a message")
        self.assertEqual(message.from_email, "from@domain.com")
        self.assertEqual(message.to, [abstract_user.email])


@override_settings(AUTHENTICATION_BACKENDS=['authtools.backends.CaseInsensitiveUsernameFieldModelBackend'])
class CaseInsensitiveTest(TestCase):
    form_class = CaseInsensitiveUsernameFieldCreationForm

    def get_form_data(self, data):
        base_data = {
            'auth.User': {},
            'authtools.User': {
                'name': 'Test Name',
            },
            'tests.User': {
                'full_name': 'Francis Underwood',
                'preferred_name': 'Frank',
            }
        }
        defaults = base_data[settings.AUTH_USER_MODEL]
        defaults.update(data)
        return defaults

    def test_case_insensitive_login_works(self):
        password = 'secret'
        form = self.form_class(self.get_form_data({
            User.USERNAME_FIELD: 'TEst@exAmPle.Com',
            'password1': password,
            'password2': password,
        }))
        self.assertTrue(form.is_valid(), form.errors)
        form.save()

        self.assertTrue(self.client.login(
            username='test@example.com',
            password=password,
        ))

        self.assertTrue(self.client.login(
            username='TEST@EXAMPLE.COM',
            password=password,
        ))


@override_settings(AUTHENTICATION_BACKENDS=['authtools.backends.CaseInsensitiveEmailModelBackend'])
class CaseInsensitiveAliasTest(TestCase):
    """Test that the aliases still work as well"""
    form_class = CaseInsensitiveEmailUserCreationForm


try:
    from auth_tests.test_views import LoginSuccessURLAllowedHostsTest

    @override_settings(ROOT_URLCONF='tests.urls')
    class LoginSuccessURLAllowedHostsTest(AuthViewsTestCaseDataMixin, LoginSuccessURLAllowedHostsTest):
        if settings.AUTH_USER_MODEL == 'auth.User':
            default_login = 'testclient'
        else:
            default_login = 'testclient@example.com'

        def test_success_url_allowed_hosts_same_host(self):
            response = self.client.post('/login/allowed_hosts/', {
                'username': self.default_login,
                'password': 'password',
                'next': 'https://testserver/home',
            })
            self.assertIn(SESSION_KEY, self.client.session)
            self.assertRedirects(response, 'https://testserver/home', fetch_redirect_response=False)

        def test_success_url_allowed_hosts_safe_host(self):
            response = self.client.post('/login/allowed_hosts/', {
                'username': self.default_login,
                'password': 'password',
                'next': 'https://otherserver/home',
            })
            self.assertIn(SESSION_KEY, self.client.session)
            self.assertRedirects(response, 'https://otherserver/home', fetch_redirect_response=False)

        def test_success_url_allowed_hosts_unsafe_host(self):
            response = self.client.post('/login/allowed_hosts/', {
                'username': self.default_login,
                'password': 'password',
                'next': 'https://evil/home',
            })
            self.assertIn(SESSION_KEY, self.client.session)
            self.assertRedirects(response, '/accounts/profile/', fetch_redirect_response=False)

except ImportError:
    pass
