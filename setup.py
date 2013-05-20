#!/usr/bin/env python
from setuptools import setup, find_packages
import subprocess
import os

__doc__ = """
Custom user model app for Django featuring email as username.
"""


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


install_requires = [
    'Django>=1.5',
]

version = (0, 0, 1, 'alpha')


def get_version():
    number = '.'.join(map(str, version[:3]))
    stage = version[3]
    if stage == 'final':
        return number
    elif stage == 'alpha':
        process = subprocess.Popen('git rev-parse HEAD'.split(), stdout=subprocess.PIPE)
        stdout, stderr = process.communicate()
        return number + '-' + stdout.strip()[:8]

setup(
    name='authuser',
    version=get_version(),
    description=__doc__,
    long_description=read('README.md'),
    packages=[package for package in find_packages() if package.startswith('authuser')],
    install_requires=install_requires,
    zip_safe=False,
    include_package_data=True,
)
