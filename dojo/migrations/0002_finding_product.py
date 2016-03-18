# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='finding',
            name='product',
            field=models.ForeignKey(related_name='findings_o2m', blank=True, to='dojo.Product', null=True),
        ),
    ]
