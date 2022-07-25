#!/usr/bin/env python
import io
import os

from setuptools import setup, find_packages

__doc__ = "Custom user model app for Django featuring email as username."


def read(fname):
    return io.open(os.path.join(os.path.dirname(__file__), fname), encoding="utf-8").read()


install_requires = [
    'Django>=2.2',
]

setup(
    name='django-authtools',
    version='2.0',
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
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
    ],
)
