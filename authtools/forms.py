from __future__ import unicode_literals

from django import forms, VERSION as DJANGO_VERSION
from django.forms.utils import flatatt
from django.contrib.auth.forms import (
    ReadOnlyPasswordHashField, ReadOnlyPasswordHashWidget,
    PasswordResetForm as OldPasswordResetForm,
    UserChangeForm as DjangoUserChangeForm,
    AuthenticationForm as DjangoAuthenticationForm,
)
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import identify_hasher, UNUSABLE_PASSWORD_PREFIX
from django.utils.translation import ugettext_lazy as _, ugettext
from django.utils.html import format_html

User = get_user_model()


def is_password_usable(pw):
    """Decide whether a password is usable only by the unusable password prefix.

    We can't use django.contrib.auth.hashers.is_password_usable either, because
    it not only checks against the unusable password, but checks for a valid
    hasher too. We need different error messages in those cases.
    """

    return not pw.startswith(UNUSABLE_PASSWORD_PREFIX)


class BetterReadOnlyPasswordHashWidget(ReadOnlyPasswordHashWidget):
    """
    A ReadOnlyPasswordHashWidget that has a less intimidating output.
    """
    def render(self, name, value, attrs=None, renderer=None):
        final_attrs = flatatt(self.build_attrs(attrs))

        if not value or not is_password_usable(value):
            summary = ugettext("No password set.")
        else:
            try:
                identify_hasher(value)
            except ValueError:
                summary = ugettext("Invalid password format or unknown"
                                   " hashing algorithm.")
            else:
                summary = ugettext('*************')

        return format_html('<div{attrs}><strong>{summary}</strong></div>',
                           attrs=final_attrs, summary=summary)


class UserCreationForm(forms.ModelForm):
    """
    A form for creating new users. Includes all the required
    fields, plus a repeated password.
    """

    error_messages = {
        'password_mismatch': _("The two password fields didn't match."),
        'duplicate_username': _("A user with that %(username)s already exists."),
    }

    password1 = forms.CharField(label=_("Password"), widget=forms.PasswordInput)
    password2 = forms.CharField(label=_("Password confirmation"),
                                widget=forms.PasswordInput,
                                help_text=_("Enter the same password as above,"
                                            " for verification."))

    class Meta:
        model = User
        fields = (User.USERNAME_FIELD,) + tuple(User.REQUIRED_FIELDS)

    def __init__(self, *args, **kwargs):
        super(UserCreationForm, self).__init__(*args, **kwargs)

        def validate_uniqueness_of_username_field(value):
            # Since User.username is unique, this check is redundant,
            # but it sets a nicer error message than the ORM. See #13147.
            try:
                User._default_manager.get_by_natural_key(value)
            except User.DoesNotExist:
                return value
            raise forms.ValidationError(self.error_messages['duplicate_username'] % {
                'username': User.USERNAME_FIELD,
            })

        self.fields[User.USERNAME_FIELD].validators.append(validate_uniqueness_of_username_field)

    def clean_password2(self):
        # Check that the two password entries match
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError(self.error_messages['password_mismatch'])
        return password2

    def save(self, commit=True):
        # Save the provided password in hashed format
        user = super(UserCreationForm, self).save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user


class CaseInsensitiveUsernameFieldCreationForm(UserCreationForm):
    """
    This form is the same as UserCreationForm, except that usernames are lowercased before they
    are saved. This is to disallow the existence of email address usernames which differ only in
    case.
    """
    def clean_USERNAME_FIELD(self):
        username = self.cleaned_data.get(User.USERNAME_FIELD)
        if username:
            username = username.lower()

        return username

# set the correct clean method on the class so that child classes can override and call super()
setattr(
    CaseInsensitiveUsernameFieldCreationForm,
    'clean_' + User.USERNAME_FIELD,
    CaseInsensitiveUsernameFieldCreationForm.clean_USERNAME_FIELD
)

# alias for the old name for backwards-compatability
CaseInsensitiveEmailUserCreationForm = CaseInsensitiveUsernameFieldCreationForm


class UserChangeForm(forms.ModelForm):
    """
    A form for updating users. Includes all the fields on
    the user, but replaces the password field with admin's
    password hash display field.
    """
    password = ReadOnlyPasswordHashField(label=_("Password"),
        widget=BetterReadOnlyPasswordHashWidget)

    class Meta:
        model = User
        fields = '__all__'

    def __init__(self, *args, **kwargs):
        super(UserChangeForm, self).__init__(*args, **kwargs)
        f = self.fields.get('user_permissions', None)
        if f is not None:
            f.queryset = f.queryset.select_related('content_type')

    def clean_password(self):
        # Regardless of what the user provides, return the initial value.
        # This is done here, rather than on the field, because the
        # field does not have access to the initial value
        return self.initial["password"]


class AdminUserChangeForm(UserChangeForm):
    def __init__(self, *args, **kwargs):
        super(AdminUserChangeForm, self).__init__(*args, **kwargs)
        if not self.fields['password'].help_text:
            self.fields['password'].help_text = \
                DjangoUserChangeForm.base_fields['password'].help_text


class FriendlyPasswordResetForm(OldPasswordResetForm):
    error_messages = dict(getattr(OldPasswordResetForm, 'error_messages', {}))
    error_messages['unknown'] = _("This email address doesn't have an "
                                  "associated user account. Are you "
                                  "sure you've registered?")

    def clean_email(self):
        """Return an error message if the email address being reset is unknown.

        This is to revert https://code.djangoproject.com/ticket/19758
        The bug #19758 tries not to leak emails through password reset because
        only usernames are unique in Django's default user model.

        django-authtools leaks email addresses through the registration form.
        In the case of django-authtools not warning the user doesn't add any
        security, and worsen user experience.
        """

        email = self.cleaned_data['email']
        results = list(self.get_users(email))

        if not results:
            raise forms.ValidationError(self.error_messages['unknown'])
        return email


class AuthenticationForm(DjangoAuthenticationForm):
    def __init__(self, request=None, *args, **kwargs):
        super(AuthenticationForm, self).__init__(request, *args, **kwargs)
        username_field = User._meta.get_field(User.USERNAME_FIELD)
        self.fields['username'].widget = username_field.formfield().widget
