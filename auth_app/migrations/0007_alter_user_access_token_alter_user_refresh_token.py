# Generated by Django 5.1.1 on 2025-01-10 10:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('auth_app', '0006_user_access_token_user_refresh_token'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='access_token',
            field=models.CharField(blank=True, max_length=500, null=True),
        ),
        migrations.AlterField(
            model_name='user',
            name='refresh_token',
            field=models.CharField(blank=True, max_length=500, null=True),
        ),
    ]
