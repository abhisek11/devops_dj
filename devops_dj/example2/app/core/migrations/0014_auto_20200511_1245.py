# Generated by Django 3.0.5 on 2020-05-11 12:45

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0013_auto_20200508_1553'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='industry',
            options={'verbose_name_plural': 'Industry'},
        ),
        migrations.AlterModelOptions(
            name='profile',
            options={'verbose_name_plural': 'profile'},
        ),
        migrations.AlterModelOptions(
            name='regions',
            options={'verbose_name_plural': 'Regions'},
        ),
        migrations.AlterModelOptions(
            name='reportdumpuploadbkp',
            options={'verbose_name_plural': 'Report Dump Upload bkp'},
        ),
        migrations.AlterModelOptions(
            name='reportfeedbackmetadata',
            options={'verbose_name_plural': 'Report Feedback MetaData'},
        ),
        migrations.AlterModelOptions(
            name='reportfeedbackrecord',
            options={'verbose_name_plural': 'Report Feedback Record'},
        ),
        migrations.AlterModelOptions(
            name='reportfeedbackrecordauthresultsdkim',
            options={'verbose_name_plural': 'Report Feedback Record Auth Results Dkim'},
        ),
        migrations.AlterModelOptions(
            name='reportfeedbackrecordauthresultsspf',
            options={'verbose_name_plural': 'Report Feedback Record Auth Results Spf'},
        ),
        migrations.AlterModelOptions(
            name='tenant',
            options={'verbose_name_plural': 'Tenant'},
        ),
        migrations.AlterModelTable(
            name='industry',
            table=None,
        ),
        migrations.AlterModelTable(
            name='profile',
            table=None,
        ),
        migrations.AlterModelTable(
            name='regions',
            table=None,
        ),
        migrations.AlterModelTable(
            name='reportdumpuploadbkp',
            table=None,
        ),
        migrations.AlterModelTable(
            name='reportfeedbackmetadata',
            table=None,
        ),
        migrations.AlterModelTable(
            name='reportfeedbackrecord',
            table=None,
        ),
        migrations.AlterModelTable(
            name='reportfeedbackrecordauthresultsdkim',
            table=None,
        ),
        migrations.AlterModelTable(
            name='reportfeedbackrecordauthresultsspf',
            table=None,
        ),
        migrations.AlterModelTable(
            name='tenant',
            table=None,
        ),
    ]

