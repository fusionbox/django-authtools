import datetime

from unittest import skipIf, skipUnless

from django.core import mail

from django.test import TestCase
from django.test.utils import override_settings
from django.utils.encoding import force_str
from django.utils.translation import gettext as _
from django.forms.fields import Field
from django.conf import settings
from django.contrib.auth import get_user_model

from authtools.admin import BASE_FIELDS
from authtools.forms import (
    UserCreationForm,
    UserChangeForm,
    CaseInsensitiveUsernameFieldCreationForm,
    CaseInsensitiveEmailUserCreationForm,
)

User = get_user_model()


def skipIfNotCustomUser(test_func):
    return skipIf(settings.AUTH_USER_MODEL == 'auth.User', 'Built-in User model in use')(test_func)


def skipIfCustomUser(test_func):
    """
    Copied from django.contrib.auth.tests.utils, This is deprecated in the future, but we still
    need it for some of our tests.
    """
    return skipIf(settings.AUTH_USER_MODEL != 'auth.User', 'Custom user model in use')(test_func)


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
            force_str(form.error_messages['duplicate_username']) % {'username': self.username}])

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
                         [force_str(form.error_messages['password_mismatch'])])

    def test_both_passwords(self):
        # One (or both) passwords weren't given
        data = {self.username: 'jsmith'}
        form = UserCreationForm(data)
        required_error = [force_str(Field.default_error_messages['required'])]
        self.assertFalse(form.is_valid())
        self.assertEqual(form['password1'].errors, required_error)
        self.assertEqual(form['password2'].errors, required_error)

        data['password2'] = 'test123'
        form = UserCreationForm(data)
        self.assertFalse(form.is_valid())
        self.assertEqual(form['password1'].errors, required_error)
        self.assertEqual(form['password2'].errors, [])

    def test_normalizes_email(self):
        data = {
            'password1': 'test123',
            'password2': 'test123',
            self.username: 'test@Example.com',
        }
        if settings.AUTH_USER_MODEL == 'auth.User':
            data['email'] = 'test@Example.com'
        elif settings.AUTH_USER_MODEL == 'authtools.User':
            data['name'] = 'John Smith'
        elif settings.AUTH_USER_MODEL != 'tests.User':
            assert False, "I don't know your user model"

        form = UserCreationForm(data)
        self.assertTrue(form.is_valid())
        u = form.save()
        self.assertEqual(u.email, 'test@example.com')

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

    def test_uses_auth_password_validators(self):
        with self.settings(
            AUTH_PASSWORD_VALIDATORS=[
                {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'}
            ]
        ):
            data = {
                self.username: 'jsmith@example.com',
                'password1': 'a',
                'password2': 'a',
            }

            if settings.AUTH_USER_MODEL == 'authtools.User':
                data['name'] = 'John Smith'

            form = UserCreationForm(data)
            self.assertFalse(form.is_valid())


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


@skipIfNotCustomUser
class NormalizeEmailTestCase(TestCase):
    def setUp(self):
        self.password = 'secret'
        self.user = User.objects.create_user(
            email='test@Foo.com',
            password=self.password,
        )

    def test_create_user_normalizes_email(self):
        self.assertEqual(self.user.email, 'test@foo.com')

    def test_login_email_domain_is_case_insensitive(self):
        self.assertTrue(self.client.login(
            username='test@foo.com',
            password=self.password,
        ))
        self.assertTrue(self.client.login(
            username='test@Foo.com',
            password=self.password,
        ))

    def test_login_email_local_part_is_case_sensitive(self):
        self.assertFalse(self.client.login(
            username='Test@foo.com',
            password=self.password,
        ))
