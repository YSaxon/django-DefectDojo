# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations

def default_product_in_finding(apps, schema_editor):
    MyModel = apps.get_model('dojo', 'finding')
    for finding in MyModel.objects.all():
        if finding.product == None:
           finding.product = finding.test.engagement.product
           finding.save()


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0002_finding_product'),
    ]

    operations = [
        migrations.RunPython(default_product_in_finding, reverse_code=migrations.RunPython.noop),       
        migrations.AlterField(
            model_name='finding',
            name='product',
            field=models.ForeignKey(related_name='findings_o2m', to='dojo.Product', null=False, blank=False),
        ),
    ]
