# Generated by Django 3.0 on 2019-12-09 14:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('oidc_op', '0017_auto_20191209_1441'),
    ]

    operations = [
        migrations.AddField(
            model_name='oidcendpointssodb',
            name='sub_clean',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
    ]
