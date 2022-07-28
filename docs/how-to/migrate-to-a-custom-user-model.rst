How To Migrate to a Custom User Model
=====================================


If you are using the built-in Django User model and you want to switch to an
authtools-based User model, there are certain steps you have to take in order
to keep all of your data. These are steps that have worked for me in the past,
maybe they will help to inform your journey.

This tutorial assumes that you already have users in your database and that you need
to preserve that data. If you don't already have users in your database, you can
switch easily already.

Step 1: Backup your database
----------------------------

There are several commands for doing this depending on your RDBMS (``pg_dump``,
``mysqldump``, ``cp``). If you don't want to worry about those, you could also
look for a solution like `django-backupdb
<https://github.com/fusionbox/django-backupdb>`_. You *do not* want to start
this process without having a backup of your database.


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

If your code has any references to Django's ``User`` model, you will have to go through and replace them with `generic references <https://docs.djangoproject.com/en/4.0/topics/auth/customizing/#referencing-the-user-model>`_. In most places, this means using ``get_user_model()`` instead of ``User``.
For models with a database relationship to ``User``, you should use ``settings.AUTH_USER_MODEL``.


Step 3: Seize control
---------------------

Generate an initial migration for the ``accounts`` app. ::

    $ python manage.py makemigrations accounts

If you are working on a new database and are running the migrations from
scratch, you can run that migration normally. However, if you are working on an
existing database, this migration will fail because the tables it attempts to
create already exist. In this type of situation, the solution would usually be to fake apply the migration, 
but doing so in this case will cause Django to raise an :class:`InconsistentMigrationHistory` exception.
There a couple of ways around this. 

One solution would be to delete all your old migration files, truncate the migrations table in the database, 
create new migrations, and then fake apply them as outlined `in this tutorial <https://rasulkireev.com/custom-user-model-mid-project-django/>`_.

This is not ideal. Instead, I suggest another solution that preserves your migration history. Thanks to `this blog post by Tobias McNulty <https://www.caktusgroup.com/blog/2019/04/26/how-switch-custom-django-user-model-mid-project/>`_ for the idea.

Start by opening up a database shell. ::

    $ python manage.py dbshell

Then manually add the migration to the database like this: ::

    INSERT INTO django_migrations (app, name, applied) VALUES ('accounts', '0001_initial', CURRENT_TIMESTAMP);

Finally, update the ``django_content_type`` table with the new ``app_label`` so that existing references will point to your new user model. You can then exit the shell. ::

    UPDATE django_content_type SET app_label = 'accounts' WHERE app_label = 'auth' and model = 'user';

.. warning ::

    Make sure to test this process in a staging environment. If your deployment process automatically runs ``migrate``, you will need to run the 2 SQL statements above
    beforehand or the migration command will fail.




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

2. Add ``authtools`` to your ``INSTALLED_APPS``. ::

    INSTALLED_APPS = (
        ...
        'authtools',
        ...
    )


3.  Add the fields that I want to User. In this case, all I want to add is
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
    that data, I will get rid of those fields in step 5.


4.  Make a migration to add those fields. ::

        $ python manage.py makemigrations accounts


5.  Add python functions to run with the migration that consolidate ``first_name``/``last_name`` into ``name`` (and vice-versa when rolling-back). ::

        def forwards(apps, schema_editor):
            User = apps.get_model('accounts', 'User')
            for user in User.objects.all():
                user.name = user.first_name + ' ' + user.last_name
                user.save()
            
        def backwards(apps, schema_editor):
            User = apps.get_model('accounts', 'User')
            for user in User.objects.all():
                user.first_name, _, user.last_name = user.name.partition(' ')
                user.save()

    Add these functions to the list of operations in the generated migration file. ::

        operations = [
            ...,
            migrations.RunPython(forwards, backwards),
        ]

    The backwards migration does make some assumptions about how names work,
    but those are the assumptions you are forced to make when using a system
    that assumes people have two names.


6.  Delete the columns you don't want on your User model. For me, that's
    ``username``, ``first_name``, and ``last_name``. My User model now looks
    like this::

        class User(AbstractNamedUser):
            class Meta:
                db_table = 'auth_user'


7.  Generate a migration that deletes those extra fields. ::

        $ python manage.py makemigrations accounts

8.  Run the migrations. ::

        $ python manage.py migrate accounts


9.  Watch `YouTube <http://www.youtube.com/watch?v=9bZkp7q19f0>`_. You are
    done.

.. _this blog post by Tobias McNulty: https://www.caktusgroup.com/blog/2019/04/26/how-switch-custom-django-user-model-mid-project/
