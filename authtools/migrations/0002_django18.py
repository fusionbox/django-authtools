from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('authtools', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='last_login',
            field=models.DateTimeField(null=True, verbose_name='last login', blank=True),
        ),
    ]
