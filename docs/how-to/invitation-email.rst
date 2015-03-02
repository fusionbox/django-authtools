How To Create Users Without Setting Their Password
==================================================

When creating a new user through Django's admin interface, you are asked
to enter the new user's password. This is less than ideal, because it
requires the admin to think of a password for someone else, communicate
it to them somehow, and then the user must remember to change it. A
better way would be to send a password-reset email to the new user,
allowing them to enter their own password.

To implement this, we need to provide a user-creation form that has an
optional (instead of required, like the built-in form) password field
and a User admin that uses the form and sends the password-reset email
when creating a new user.


We'll subclass :class:`~authtools.forms.UserCreationForm` to create a form with
optional password fields::

    from django import forms
    from authtools.forms import UserCreationForm

    class UserCreationForm(UserCreationForm):
        """
        A UserCreationForm with optional password inputs.
        """

        def __init__(self, *args, **kwargs):
            super(UserCreationForm, self).__init__(*args, **kwargs)
            self.fields['password1'].required = False
            self.fields['password2'].required = False
            # If one field gets autocompleted but not the other, our 'neither
            # password or both password' validation will be triggered.
            self.fields['password1'].widget.attrs['autocomplete'] = 'off'
            self.fields['password2'].widget.attrs['autocomplete'] = 'off'

        def clean_password2(self):
            password1 = self.cleaned_data.get("password1")
            password2 = super(UserCreationForm, self).clean_password2()
            if bool(password1) ^ bool(password2):
                raise forms.ValidationError("Fill out both fields")
            return password2

Then an admin class that uses our form and sends the email::

    from django.contrib.auth import get_user_model
    from django.contrib.auth.forms import PasswordResetForm
    from django.utils.crypto import get_random_string
    from authtools.admin import NamedUserAdmin

    User = get_user_model()

    class UserAdmin(NamedUserAdmin):
        """
        A UserAdmin that sends a password-reset email when creating a new user,
        unless a password was entered.
        """
        add_form = UserCreationForm
        add_fieldsets = (
            (None, {
                'description': (
                    "Enter the new user's name and email address and click save."
                    " The user will be emailed a link allowing them to login to"
                    " the site and set their password."
                ),
                'fields': ('email', 'name',),
            }),
            ('Password', {
                'description': "Optionally, you may set the user's password here.",
                'fields': ('password1', 'password2'),
                'classes': ('collapse', 'collapse-closed'),
            }),
        )

        def save_model(self, request, obj, form, change):
            if not change and (not form.cleaned_data['password1'] or not obj.has_usable_password()):
                # Django's PasswordResetForm won't let us reset an unusable
                # password. We set it above super() so we don't have to save twice.
                obj.set_password(get_random_string())
                reset_password = True
            else:
                reset_password = False

            super(UserAdmin, self).save_model(request, obj, form, change)

            if reset_password:
                reset_form = PasswordResetForm({'email': obj.email})
                assert reset_form.is_valid()
                reset_form.save(
                    request=request,
                    use_https=request.is_secure(),
                    subject_template_name='registration/account_creation_subject.txt',
                    email_template_name='registration/account_creation_email.html',
                )

Using :class:`django:django.contrib.auth.forms.PasswordResetForm` allows us to
share the email-sending code with Django. If you wanted to change the template
the email uses, ``email_template_name`` would be the place to do it.

Now we can replace the installed UserAdmin with our own. ::

    from django.contrib import admin
    admin.site.unregister(User)
    admin.site.register(User, UserAdmin)


You can view the :download:`complete admin.py file here. <admin.py>`
