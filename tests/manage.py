#!/usr/bin/env python
import os
import sys
import warnings

import django
if django.VERSION[:2] == (1, 6):
    # This is only necessary for Django 1.6
    from django.contrib.auth.tests import custom_user
    custom_user.AbstractUser._meta.local_many_to_many = []
    custom_user.PermissionsMixin._meta.local_many_to_many = []

warnings.simplefilter('error')

if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")

    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)
