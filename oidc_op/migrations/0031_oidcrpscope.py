# Generated by Django 3.0 on 2020-07-22 13:31

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('oidc_op', '0030_oidcsession_code'),
    ]

    operations = [
        migrations.CreateModel(
            name='OidcRPScope',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('modified', models.DateTimeField(auto_now=True)),
                ('scope', models.CharField(blank=True, max_length=254, null=True)),
                ('client', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='oidc_op.OidcRelyingParty')),
            ],
            options={
                'verbose_name': 'Relying Party Scope',
                'verbose_name_plural': 'Relying Parties Scopes',
                'unique_together': {('client', 'scope')},
            },
        ),
    ]
