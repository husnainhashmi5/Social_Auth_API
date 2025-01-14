# Generated by Django 5.1.1 on 2025-01-10 07:10

import phonenumber_field.modelfields
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('auth_app', '0004_user_otp_created_at'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='phone_number',
            field=phonenumber_field.modelfields.PhoneNumberField(blank=True, max_length=128, null=True, region=None, unique=True),
        ),
        migrations.AddField(
            model_name='user',
            name='phone_otp',
            field=models.CharField(blank=True, max_length=6, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='phone_otp_created_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
