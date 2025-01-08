# Generated by Django 5.1.1 on 2025-01-08 14:23

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('socialaccount', '0006_alter_socialaccount_extra_data'),
    ]

    operations = [
        migrations.CreateModel(
            name='CustomSocialAccount',
            fields=[
                ('socialaccount_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='socialaccount.socialaccount')),
            ],
            bases=('socialaccount.socialaccount',),
        ),
    ]