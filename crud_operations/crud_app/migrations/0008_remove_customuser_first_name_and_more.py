# Generated by Django 5.0.6 on 2024-06-05 00:23

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('crud_app', '0007_alter_customuser_email'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='customuser',
            name='first_name',
        ),
        migrations.RemoveField(
            model_name='customuser',
            name='is_active',
        ),
        migrations.RemoveField(
            model_name='customuser',
            name='is_staff',
        ),
        migrations.RemoveField(
            model_name='customuser',
            name='last_name',
        ),
    ]
