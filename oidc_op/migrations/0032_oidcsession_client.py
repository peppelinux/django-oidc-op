# Generated by Django 3.0 on 2020-07-25 17:21

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('oidc_op', '0031_oidcrpscope'),
    ]

    operations = [
        migrations.AddField(
            model_name='oidcsession',
            name='client',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='oidc_op.OidcRelyingParty'),
        ),
    ]
