# Generated by Django 3.0.5 on 2020-05-22 23:13

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0016_auto_20200522_2127'),
    ]

    operations = [
        migrations.AlterField(
            model_name='reportfeedbackrecord',
            name='count',
            field=models.IntegerField(blank=True, null=True),
        ),
    ]
