"""
We're able to borrow most of django's auth view tests.

"""
import collections
import contextlib
import itertools
import warnings

try:
    from unittest import skipIf, skipUnless
except ImportError:  # Python < 2.7
    from django.utils.unittest import skipIf, skipUnless

from django.core import mail
from django.core.urlresolvers import reverse
from django.contrib.auth import REDIRECT_FIELD_NAME, get_user_model
from django.contrib.auth.forms import AuthenticationForm
from django.utils.http import urlquote
from django.test import TestCase
from django.test.client import RequestFactory
from django.test.utils import override_settings
from django.utils.encoding import force_text
from django.utils.translation import ugettext as _
from django.forms.fields import Field
from django.conf import settings

from authtools.views import LoginView

from auth_tests.test_views import (
    AuthViewNamedURLTests,
    PasswordResetTest,
    ChangePasswordTest,
    LoginTest,
    LoginURLSettings,
    LogoutTest,
)
from auth_tests.test_forms import UserChangeFormTest


from authtools.admin import BASE_FIELDS
from authtools.forms import (
    UserCreationForm,
    UserChangeForm,
    FriendlyPasswordResetForm,
    CaseInsensitiveUsernameFieldCreationForm,
    CaseInsensitiveEmailUserCreationForm,
)
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


@override_settings(ROOT_URLCONF='authtools.urls')
class AuthViewNamedURLTests(AuthViewNamedURLTests):
    if settings.AUTH_USER_MODEL == 'authtools.User':
        fixtures = ['authtoolstestdata.json']
    elif settings.AUTH_USER_MODEL == 'tests.User':
        fixtures = ['customusertestdata.json']


class UtilsTest(TestCase):
    def test_resolve_lazy_unicode(self):
        self.assertTrue(resolve_url_lazy(u'/'))


@override_settings(ROOT_URLCONF='tests.urls')
class PasswordResetTest(EmailLoginMixin, PasswordResetTest):
    test_admin_reset = None
    # These text the next_page parameter, but we just use success_url
    test_reset_custom_redirect_named = None
    test_confirm_redirect_custom_named = None
    # This tests extra_email_context, we don't support that yet
    test_extra_email_context = None
    # these reference the builtin user model
    test_confirm_display_user_from_form = None

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
        with self.assertNumQueries(1):
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

        # verify that we're actually logged in
        response = self.client.get('/login_required/')
        self.assertEqual(response.status_code, 200)


@override_settings(ROOT_URLCONF='authtools.urls')
class ChangePasswordTest(EmailLoginMixin, ChangePasswordTest):

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


@override_settings(ROOT_URLCONF='authtools.urls')
class LoginTest(EmailLoginMixin, LoginTest):
    # the built-in tests depend on the django urlpatterns (they reverse
    # django.contrib.auth.views.login)

    if settings.AUTH_USER_MODEL == 'auth.User':
        default_login = 'testclient'
    else:
        default_login = 'testclient@example.com'

    # these reference the builtin user model
    test_session_key_flushed_on_login_after_password_change = None
    test_session_key_flushed_on_login_after_password_changetest_login_session_without_hash_session_key = None


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
class LoginURLSettings(LoginURLSettings):
    if settings.AUTH_USER_MODEL == 'authtools.User':
        fixtures = ['authtoolstestdata.json']
    elif settings.AUTH_USER_MODEL == 'tests.User':
        fixtures = ['customusertestdata.json']


@override_settings(ROOT_URLCONF='tests.urls')
class LogoutTest(EmailLoginMixin, LogoutTest):
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
class UserChangeFormTest(UserChangeFormTest):
    def test_better_readonly_password_widget(self):
        user = User.objects.get(username='testclient')
        form = UserChangeForm(instance=user)

        self.assertIn(_('*************'), form.as_table())


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
