# Generated by Django 3.1.1 on 2021-05-15 10:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('oidc_provider', '0005_oidcsession_sid_encrypted'),
    ]

    operations = [
        migrations.AlterField(
            model_name='oidcrpgranttype',
            name='grant_type',
            field=models.CharField(choices=[('authorization_code', 'authorization_code'), ('urn:ietf:params:oauth:grant-type:jwt-bearer',
                                                                                           'urn:ietf:params:oauth:grant-type:jwt-bearer'), ('refresh_token', 'refresh_token')], max_length=60),
        ),
    ]
