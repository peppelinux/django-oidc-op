# Generated by Django 3.0 on 2019-12-04 13:56

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('oidc_op', '0002_auto_20191204_1349'),
    ]

    operations = [
        migrations.AlterField(
            model_name='oidcrelyingparty',
            name='client_salt',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
    ]
