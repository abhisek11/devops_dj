# Generated by Django 3.0.5 on 2020-05-05 06:12

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0005_reportdumpuploadbkp_file_name'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='reportfeedbackrecord',
            name='dkim_domain',
        ),
        migrations.RemoveField(
            model_name='reportfeedbackrecord',
            name='dkim_result',
        ),
        migrations.RemoveField(
            model_name='reportfeedbackrecord',
            name='dkim_selector',
        ),
        migrations.RemoveField(
            model_name='reportfeedbackrecord',
            name='spf_domain',
        ),
        migrations.RemoveField(
            model_name='reportfeedbackrecord',
            name='spf_result',
        ),
        migrations.RemoveField(
            model_name='reportfeedbackrecord',
            name='spf_scope',
        ),
    ]
