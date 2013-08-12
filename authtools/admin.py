from __future__ import unicode_literals

import copy

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from django.contrib.auth import get_user_model
from django.utils.translation import ugettext_lazy as _

from authtools.models import User
from authtools.forms import UserCreationForm, AdminUserChangeForm

USERNAME_FIELD = get_user_model().USERNAME_FIELD

REQUIRED_FIELDS = (USERNAME_FIELD,) + tuple(get_user_model().REQUIRED_FIELDS)

BASE_FIELDS = (None, {
    'fields': REQUIRED_FIELDS + ('password',),
})

SIMPLE_PERMISSION_FIELDS = (_('Permissions'), {
    'fields': ('is_active', 'is_staff', 'is_superuser',),
})

ADVANCED_PERMISSION_FIELDS = copy.deepcopy(SIMPLE_PERMISSION_FIELDS)
ADVANCED_PERMISSION_FIELDS[1]['fields'] += ('groups', 'user_permissions',)

DATE_FIELDS = (_('Important dates'), {
    'fields': ('last_login', 'date_joined',),
})


class StrippedUserAdmin(DjangoUserAdmin):
    # The forms to add and change user instances
    add_form_template = None
    add_form = UserCreationForm
    form = AdminUserChangeForm

    # The fields to be used in displaying the User model.
    # These override the definitions on the base UserAdmin
    # that reference specific fields on auth.User.
    list_display = ('is_active', USERNAME_FIELD, 'is_superuser', 'is_staff',)
    list_display_links = (USERNAME_FIELD,)
    list_filter = ('is_superuser', 'is_staff', 'is_active',)
    fieldsets = (
        BASE_FIELDS,
        SIMPLE_PERMISSION_FIELDS,
    )
    add_fieldsets = (
        (None, {
            'fields': REQUIRED_FIELDS + (
                'password1',
                'password2',
            ),
        }),
    )
    search_fields = (USERNAME_FIELD,)
    ordering = None
    filter_horizontal = tuple()
    readonly_fields = ('last_login', 'date_joined')


class StrippedNamedUserAdmin(StrippedUserAdmin):
    list_display = ('is_active', 'email', 'name', 'is_superuser', 'is_staff',)
    list_display_links = ('email', 'name',)
    search_fields = ('email', 'name',)


class UserAdmin(StrippedUserAdmin):
    fieldsets = (
        BASE_FIELDS,
        ADVANCED_PERMISSION_FIELDS,
        DATE_FIELDS,
    )
    filter_horizontal = ('groups', 'user_permissions',)


class NamedUserAdmin(UserAdmin, StrippedNamedUserAdmin):
    pass


# If the model has been swapped, this is basically a noop.
admin.site.register(User, NamedUserAdmin)
