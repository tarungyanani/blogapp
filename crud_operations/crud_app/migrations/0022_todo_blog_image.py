# Generated by Django 5.0.6 on 2024-06-25 09:19

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('crud_app', '0021_alter_profile_image'),
    ]

    operations = [
        migrations.AddField(
            model_name='todo',
            name='blog_image',
            field=models.ImageField(blank=True, null=True, upload_to='blog_images/'),
        ),
    ]
