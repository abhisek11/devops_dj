# Generated by Django 3.0.5 on 2020-05-04 21:13

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0003_reportdumpuploadbkp_reportfeedbackmetadata_reportfeedbackrecord'),
    ]

    operations = [
        migrations.AlterField(
            model_name='reportfeedbackmetadata',
            name='begin',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='reportfeedbackmetadata',
            name='end',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
