Contributing
------------

We welcome contributions of all sizes, whether it be a small text change or a large new feature.
Here are are some steps for getting started contributing.



Getting Started
===============

1.  Install the development requirements::

        $ pip install -r requirements-dev.txt


Running Tests
=============

The best way to run the tests is using `tox`_. You can run the tests on all of our supported
Python and Django versions by running::

    $ tox

You can also run specific targets using the ``-e`` flag. ::

    $ tox -e py33-dj18

A full list of available tox environments is in the ``tox.ini`` configuration file.

django-authtools comes with a test suite that inherits from the built-in Django auth test suite.
This helps us ensure compatibility with Django and that we can get a little bit of code reuse. The
tests are run three times against three different User models.

You can get a test coverage report by running ``make coverage``. We do not strive for 100% coverage
on django-authtools, but it is still a useful metric.

.. _tox: http://tox.readthedocs.org/en/latest/


Building Documentation
======================

You can build the documentation by running ::

    $ make docs

If you are editing the ``README.rst`` file, please make sure that it compiles correctly using the
``longtest`` command that is provided by ``zest.releaser``. ::

    $ longtest
