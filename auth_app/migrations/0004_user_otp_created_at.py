# Generated by Django 5.1.1 on 2025-01-09 12:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('auth_app', '0003_user_otp'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='OTP_created_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]