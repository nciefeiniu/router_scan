# Generated by Django 3.2.22 on 2023-10-28 21:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scan', '0002_cvedata_routercve'),
    ]

    operations = [
        migrations.AddField(
            model_name='scanresult',
            name='region',
            field=models.CharField(blank=True, max_length=32, null=True, verbose_name='哪个州'),
        ),
    ]
