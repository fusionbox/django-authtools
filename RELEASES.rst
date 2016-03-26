Release Process
===============

django-authtools uses `zest.releaser`_ to manage releases. For a fuller
understanding of the release process, please read zest.releaser's
documentation, this document is more of a cheat sheet.

Getting Setup
-------------

You will need to install zest.releaser::

    $ pip install -r requirements-dev.txt

You will also need to configure your ``.pypirc`` file to have the PyPI
credentials. Ask one of the other Fusionbox Programmers how to do that.

Releases
--------

The process for releases is the same regardless of whether it's a patch, minor,
or major release. It is as follows.

1. Add the changes to ``CHANGES.rst``. Don't commit. NOTE: You do not have to replace "(unreleased)"
   with the desired release date; zest.releaser will do this automatically.
2. Run the ``longtest`` command to make sure that the ``README.rst`` and
   ``CHANGES.rst`` files are valid.
3. Commit changes with a commit message like "CHANGES for 1.1.0".
4. Run the ``fullrelease`` command.


Editing the Changelog
---------------------

Editing the changelog is very important. It is where we write down all of our
release notes and upgrade instructions. Please spend time when editing the
changelog.

One way to help getting the changes for new versions is to run the following
commands::

    $ git tag | sort -rn # figure out the latest tag (imagine it's 1.0.0)
    1.0.0
    $ git log HEAD ^1.0.0

This will show all the commits that are in HEAD that weren't in the last
release.

If possible, it's nice to add a credit line with the author's name and the
issue number of GitHub.

Deciding on a Version Number
----------------------------

Here are some nominal guidelines for deciding on version numbers when cutting
releases. If you feel the need to deviate from them, go ahead. If you find
yourself deviating every time, please update this document.

This is not semver, but it's similar.

Patch Release (1.0.x)
^^^^^^^^^^^^^^^^^^^^^

Bug fixes, documentation, and general project maintenance.

Avoid backwards incompatible changes like the plague.

Minor Release (1.x.0)
^^^^^^^^^^^^^^^^^^^^^

New features, and anything in patch releases.

Try to avoid backwards incompatible changes, but if you feel like you need
(especially for security), it's acceptable.

Major Release (x.0.0)
^^^^^^^^^^^^^^^^^^^^^

Really Cool New Features, and anything that you include in a minor release.

Backwards incompatibility is more acceptable here, although still frowned upon.


Additional Reading
------------------

- `zest.releaser Version handling <http://zestreleaser.readthedocs.org/en/latest/versions.html>`_
- `PEP 396 - Module Version Numbers <https://www.python.org/dev/peps/pep-0396/>`_
- `PEP 440 - Version Identification and Dependency Specification <https://www.python.org/dev/peps/pep-0396/>`_

.. _zest.releaser: http://zestreleaser.readthedocs.org/
