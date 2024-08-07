# Generated by Django 5.0.6 on 2024-06-04 23:48

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('crud_app', '0005_alter_customuser_email'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='email',
            field=models.CharField(max_length=254, unique=True, validators=[django.core.validators.RegexValidator(code='invalid_email', message='Enter a valid email address.', regex='^(?=.*[a-z])(?=.*[0-9])[a-zA-Z0-9._%+-]+@(gmail\\.com|yahoo\\.com $')]),
        ),
    ]
