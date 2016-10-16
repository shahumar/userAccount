# -*- coding: utf-8 -*-
# Generated by Django 1.9.8 on 2016-10-16 08:22
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0002_account_passwordhistory'),
    ]

    operations = [
        migrations.CreateModel(
            name='EmailConfirmation',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(default=django.utils.timezone.now)),
                ('sent', models.DateTimeField(null=True)),
                ('key', models.CharField(max_length=64, unique=True)),
                ('email_address', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='accounts.EmailAddress')),
            ],
            options={
                'verbose_name_plural': 'email confirmations',
                'verbose_name': 'email confirmation',
            },
        ),
    ]
