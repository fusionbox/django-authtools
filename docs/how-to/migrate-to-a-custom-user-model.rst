How To Migrate to a Custom User Model
=====================================


If you are using the built-in Django User model and you want to switch to an
authtools-based User model, there are certain steps you have to take in order
to keep all of your data. These are steps that have worked for me in the past,
maybe they will help to inform your journey.

This tutorial assumes that you are using South for migrations. If you aren't
you probably should be using it. Unless of course, it's the future and the
`schema-alteration
<https://github.com/andrewgodwin/django/tree/schema-alteration>`_ of Django has
been completed and merged.

It also assumes that you already have users in your database and that you need
to preserve that data. If you don't already have users in your database, you
switch easily already.

This tutorial shows the easy way to migrate custom Users, keeping the same
database table.  If you want to move to your own database table, there is an
`excellent answer`_ on StackOverflow.

Step 1: Backup your database
----------------------------

There are several commands for doing this depending on your RDBMS (``pg_dump``,
``mysqldump``, ``cp``). If you don't want to worry about those, you could also
look for a solution like `django-backupdb
<https://github.com/fusionbox/django-backupdb>`_. You *do not* want to start
this process without having a backup of your database.

Steps 2 and 3 are actually completely safe.  They don't actually affect the
database.  What they do accomplish is moving the authoritative source of
control over the User model class from django to your code.


Step 2: Make a new app
----------------------

This is the app where your custom User model will live. I usually call this
app ``accounts``. ::

    $ python manage.py startapp accounts

In your new app, edit the models file and add the following::

    from django.db import models
    from django.contrib.auth.models import AbstractUser

    class User(AbstractUser):
        class Meta:
            db_table = 'auth_user'


This will put the User model in the same database table as the old one. This
is not ideal, but it is the easiest way to do this migration.

Add your ``accounts`` app to :django:setting:`INSTALLED_APPS`.

Set the :django:setting:`AUTH_USER_MODEL` setting to point to your new User
model. ::

    AUTH_USER_MODEL = 'accounts.User'


Step 3: Seize control
---------------------

Generate an initial migration for the ``accounts`` app. ::

    $ python manage.py schemamigration --initial accounts

If you are working on a new database and are running the migrations from
scratch, you can run that migration normally. However, if you are working on an
existing database, this migration will fail because the tables it attempts to
create already exist. You will have to fake run this migration. ::

    $ python manage.py migrate --fake accounts 0001

.. note ::

    If you are very certain that these migrations will *never* be run on an
    empty database, you can replace the bodies ``forwards`` and ``backwards``
    migrations with ``pass``. This is not a good idea though.


Step 4: Conquer
---------------

Your ``accounts`` app is now the authoritative source for the User model. You
are in charge now.

Go build stuff.


Optional Step 5: Customize
--------------------------

.. warning ::

    There is a potential unique constraint failure here. If you don't have
    emails for all of your users, you won't be able to migrate. If you don't
    have emails for all of your users, they won't be able to log in either, so
    you should make sure that you have all of those email addresses first.

Now that you have control of the User model, there are tons of customizations
that you can do. One thing that I like to do is treat ``email`` as the username
and get rid of ``first_name``/``last_name`` in favor of a single ``name``
field. Here's how I've done it in the past.

1.  Install django-authtools. ::

    $ pip install django-authtools


2.  Add the fields that I want to User. In this case, all I want to add is
    ``name``. ``email`` already exists on User, but I do need to make it
    unique if I'm going to treat it as a username.

    Here is an implementation of the User model using
    :class:`authtools.models.AbstractNamedUser` as a base. It preserves all of
    the fields that are on the built-in User model, but adds ``name`` and
    treats ``email`` as the username. ::

        from django.db import models
        from django.utils.translation import gettext_lazy as _

        from authtools.models import AbstractNamedUser


        class User(AbstractNamedUser):
            username = models.CharField(_('username'), max_length=30, unique=True)
            first_name = models.CharField(_('first name'), max_length=30, blank=True)
            last_name = models.CharField(_('last name'), max_length=30, blank=True)

            class Meta:
                db_table = 'auth_user'

    I still have ``first_name`` and ``last_name`` because I have to preserve
    that data, I will get rid of those fields in step 5.  When you are altering
    the schema and migrating data, the `South tutorial on data migrations`_
    recommends that you split it up into 3 steps.


3.  Make a schema migration to add those fields. ::

        $ python manage.py schemamigration --auto accounts


4.  Make a data migration to copy ``first_name``/``last_name`` into ``name``. ::

        $ python manage.py datamigration accounts consolidate_name_field

    Here is an example of a migration that does this::

        class Migration(DataMigration):
            def forwards(self, orm):
                for user in orm['accounts.User'].objects.all():
                    user.name = user.first_name + ' ' + user.last_name
                    user.save()

            def backwards(self, orm):
                for user in orm['accounts.User'].objects.all():
                    # If there are more than two names, assume that the rest
                    # are their last names.
                    user.first_name, _, user.last_name = user.name.partition(' ')
                    user.save()

    The backwards migration does make some assumptions about how names work,
    but those are the assumptions you are forced to make when using a system
    that assumes people have two names.


5.  Delete the columns you don't want on your User model. For me, that's
    ``username``, ``first_name``, and ``last_name``. My User model now looks
    like this::

        class User(AbstractNamedUser):
            class Meta:
                db_table = 'auth_user'


6.  Generate a migration that deletes those extra fields. ::

        $ python manage.py schemamigration --auto accounts

    You will be presented with a question about what to do in the backwards
    migration. The ``username`` field was non-nullable, which means it's
    impossible to go back. I would select to disable backwards migrations.


7.  Run the migrations. ::

        $ python manage.py migrate accounts


8.  Watch `YouTube <http://www.youtube.com/watch?v=9bZkp7q19f0>`_. You are
    done.

.. _excellent answer: http://stackoverflow.com/questions/14904046/migrating-existing-auth-user-data-to-new-django-1-5-custom-user-model
.. _South tutorial on data migrations: http://south.aeracode.org/wiki/Tutorial3
