# Generated by Django 5.0.8 on 2024-08-18 11:07

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('crud_app', '0032_comment_like'),
    ]

    operations = [
        migrations.AlterField(
            model_name='comment',
            name='content',
            field=models.TextField(null=True),
        ),
    ]
