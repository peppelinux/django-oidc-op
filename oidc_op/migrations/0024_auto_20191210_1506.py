# Generated by Django 3.0 on 2019-12-10 15:06

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('oidc_op', '0023_oidcsession_valid_until'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='oidcsession',
            name='sid',
        ),
        migrations.AddField(
            model_name='oidcsession',
            name='sso',
            field=models.ForeignKey(
                default=45, on_delete=django.db.models.deletion.CASCADE, to='oidc_op.OidcSessionSso'),
            preserve_default=False,
        ),
    ]
