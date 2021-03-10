# Generated by Django 3.0 on 2019-12-06 10:18

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('oidc_op', '0015_auto_20191206_0955'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='oidcrelyingparty',
            name='post_logout_redirect_uris',
        ),
        migrations.RemoveField(
            model_name='oidcrelyingparty',
            name='redirect_uris',
        ),
        migrations.AlterField(
            model_name='oidcrelyingparty',
            name='client_secret_expires_at',
            field=models.DateTimeField(
                blank=True, help_text='REQUIRED if client_secret is issued', null=True),
        ),
    ]
