#!/usr/bin/env python
import os
import sys
import warnings

warnings.simplefilter('error')

if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")

    from django.core.management import execute_from_command_line

    from django.contrib.auth.tests import custom_user
    custom_user.AbstractUser._meta.local_many_to_many = []
    custom_user.PermissionsMixin._meta.local_many_to_many = []

    execute_from_command_line(sys.argv)
