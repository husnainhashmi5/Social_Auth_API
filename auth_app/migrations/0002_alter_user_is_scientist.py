# Generated by Django 5.1.1 on 2025-01-09 12:10

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('auth_app', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='is_scientist',
            field=models.BooleanField(default=False),
        ),
    ]
