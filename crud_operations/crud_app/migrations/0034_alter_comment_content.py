# Generated by Django 5.0.8 on 2024-08-18 11:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('crud_app', '0033_alter_comment_content'),
    ]

    operations = [
        migrations.AlterField(
            model_name='comment',
            name='content',
            field=models.TextField(),
        ),
    ]
