#!/usr/bin/env python
from setuptools import setup, find_packages
import os

from authtools.version import get_version

__doc__ = ("Custom user model app for Django featuring email as username and"
           " class-based views for authentication.")


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


install_requires = [
    'Django>=1.5',
]


setup(
    name='django-authtools',
    version=get_version(),
    author='Fusionbox, Inc.',
    author_email='programmers@fusionbox.com',
    description=__doc__,
    long_description='\n\n'.join([read('README.rst'), read('CHANGES.rst')]),
    url='https://django-authtools.readthedocs.org/',
    license='BSD',
    packages=[package for package in find_packages() if package.startswith('authtools')],
    install_requires=install_requires,
    zip_safe=False,
    include_package_data=True,
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
    ],
)
