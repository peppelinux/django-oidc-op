# Generated by Django 3.0 on 2021-05-22 13:22

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('oidc_provider', '0009_auto_20210517_1803'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='oidcsession',
            name='session_info',
        ),
    ]
