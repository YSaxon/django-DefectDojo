# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import django.contrib.auth.models
import dojo.models
import django.utils.timezone
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        ('auth', '0006_require_contenttypes_0002'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='BurpRawRequestResponse',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('burpRequestBase64', models.BinaryField()),
                ('burpResponseBase64', models.BinaryField()),
            ],
        ),
        migrations.CreateModel(
            name='Check_List',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('session_management', models.CharField(default=b'none', max_length=50)),
                ('encryption_crypto', models.CharField(default=b'none', max_length=50)),
                ('configuration_management', models.CharField(default=b'', max_length=50)),
                ('authentication', models.CharField(default=b'none', max_length=50)),
                ('authorization_and_access_control', models.CharField(default=b'none', max_length=50)),
                ('data_input_sanitization_validation', models.CharField(default=b'none', max_length=50)),
                ('sensitive_data', models.CharField(default=b'none', max_length=50)),
                ('other', models.CharField(default=b'none', max_length=50)),
            ],
        ),
        migrations.CreateModel(
            name='Contact',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(max_length=100)),
                ('email', models.EmailField(max_length=254)),
                ('team', models.CharField(max_length=100)),
                ('is_admin', models.BooleanField(default=False)),
                ('is_globally_read_only', models.BooleanField(default=False)),
                ('updated', models.DateTimeField(editable=False)),
            ],
        ),
        migrations.CreateModel(
            name='CWE',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('url', models.CharField(max_length=1000)),
                ('description', models.CharField(max_length=2000)),
                ('number', models.IntegerField()),
            ],
        ),
        migrations.CreateModel(
            name='Development_Environment',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(max_length=200)),
            ],
        ),
        migrations.CreateModel(
            name='Endpoint',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('protocol', models.CharField(help_text=b"The communication protocl such as 'http', 'ftp', etc.", max_length=10, null=True, blank=True)),
                ('host', models.CharField(help_text=b"The host name or IP address, you can also include the port number. For example'127.0.0.1', '127.0.0.1:8080', 'localhost', 'yourdomain.com'.", max_length=500, null=True, blank=True)),
                ('path', models.CharField(help_text=b"The location of the resource, it should start with a '/'. For example/endpoint/420/edit", max_length=500, null=True, blank=True)),
                ('query', models.CharField(help_text=b"The query string, the question mark should be omitted.For example 'group=4&team=8'", max_length=5000, null=True, blank=True)),
                ('fragment', models.CharField(help_text=b"The fragment identifier which follows the hash mark. The hash mark should be omitted. For example 'section-13', 'paragraph-2'.", max_length=500, null=True, blank=True)),
            ],
            options={
                'ordering': ['product', 'protocol', 'host', 'path', 'query', 'fragment'],
            },
        ),
        migrations.CreateModel(
            name='Engagement',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(max_length=300, null=True, blank=True)),
                ('version', models.CharField(max_length=100, null=True, blank=True)),
                ('first_contacted', models.DateField(null=True, blank=True)),
                ('target_start', models.DateField()),
                ('target_end', models.DateField()),
                ('reason', models.CharField(max_length=2000, null=True, blank=True)),
                ('updated', models.DateTimeField(null=True, editable=False, blank=True)),
                ('active', models.BooleanField(default=True, editable=False)),
                ('test_strategy', models.URLField(null=True, blank=True)),
                ('threat_model', models.BooleanField(default=True)),
                ('api_test', models.BooleanField(default=True)),
                ('pen_test', models.BooleanField(default=True)),
                ('check_list', models.BooleanField(default=True)),
                ('status', models.CharField(default=b'', max_length=2000, null=True, choices=[(b'In Progress', b'In Progress'), (b'On Hold', b'On Hold'), (b'Completed', b'Completed')])),
                ('progress', models.CharField(default=b'threat_model', max_length=100, editable=False)),
                ('tmodel_path', models.CharField(default=b'none', max_length=1000, null=True, editable=False, blank=True)),
                ('risk_path', models.CharField(default=b'none', max_length=1000, null=True, editable=False, blank=True)),
                ('done_testing', models.BooleanField(default=False, editable=False)),
            ],
            options={
                'ordering': ['-target_start'],
            },
        ),
        migrations.CreateModel(
            name='Engagement_Type',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(max_length=200)),
            ],
        ),
        migrations.CreateModel(
            name='Finding',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('title', models.TextField(max_length=1000)),
                ('date', models.DateField(default=dojo.models.get_current_date)),
                ('cwe', models.IntegerField(default=0, null=True, blank=True)),
                ('url', models.TextField(null=True, editable=False, blank=True)),
                ('severity', models.CharField(max_length=200)),
                ('description', models.TextField()),
                ('mitigation', models.TextField()),
                ('impact', models.TextField()),
                ('references', models.TextField(null=True, db_column=b'refs', blank=True)),
                ('is_template', models.BooleanField(default=False)),
                ('active', models.BooleanField(default=True)),
                ('verified', models.BooleanField(default=True)),
                ('false_p', models.BooleanField(default=False, verbose_name=b'False Positive')),
                ('duplicate', models.BooleanField(default=False)),
                ('out_of_scope', models.BooleanField(default=False)),
                ('thread_id', models.IntegerField(default=0, editable=False)),
                ('mitigated', models.DateTimeField(null=True, editable=False, blank=True)),
                ('numerical_severity', models.CharField(max_length=4)),
                ('last_reviewed', models.DateTimeField(null=True, editable=False)),
                ('endpoints', models.ManyToManyField(to='dojo.Endpoint', blank=True)),
            ],
            options={
                'ordering': ('numerical_severity', '-date', 'title'),
            },
        ),
        migrations.CreateModel(
            name='Finding_Template',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('title', models.TextField(max_length=1000)),
                ('cwe', models.IntegerField(default=None, null=True, blank=True)),
                ('severity', models.CharField(max_length=200, null=True, blank=True)),
                ('description', models.TextField(null=True, blank=True)),
                ('mitigation', models.TextField(null=True, blank=True)),
                ('impact', models.TextField(null=True, blank=True)),
                ('references', models.TextField(null=True, db_column=b'refs', blank=True)),
                ('numerical_severity', models.CharField(max_length=4, null=True, blank=True)),
            ],
            options={
                'ordering': ['-cwe'],
            },
        ),
        migrations.CreateModel(
            name='IPScan',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('address', models.TextField(default=b'none', editable=False)),
                ('services', models.CharField(max_length=800, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='Notes',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('entry', models.CharField(max_length=2400)),
                ('date', models.DateTimeField(default=dojo.models.get_current_datetime, editable=False)),
            ],
            options={
                'ordering': ['-date'],
            },
        ),
        migrations.CreateModel(
            name='Product',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(max_length=300)),
                ('description', models.CharField(max_length=2000)),
                ('prod_manager', models.CharField(default=0, max_length=200)),
                ('tech_contact', models.CharField(default=0, max_length=200)),
                ('manager', models.CharField(default=0, max_length=200)),
                ('created', models.DateTimeField(null=True, editable=False, blank=True)),
                ('updated', models.DateTimeField(null=True, editable=False, blank=True)),
                ('tid', models.IntegerField(default=0, editable=False)),
            ],
            options={
                'ordering': ('name',),
            },
        ),
        migrations.CreateModel(
            name='Product_Line',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(max_length=300)),
                ('description', models.CharField(max_length=2000)),
            ],
        ),
        migrations.CreateModel(
            name='Product_Type',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(max_length=300)),
            ],
        ),
        migrations.CreateModel(
            name='Report',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(max_length=200)),
                ('type', models.CharField(default=b'Finding', max_length=100)),
                ('format', models.CharField(default=b'AsciiDoc', max_length=15)),
                ('task_id', models.CharField(max_length=50)),
                ('file', models.FileField(upload_to=b'reports/%Y/%m/%d', null=True, verbose_name=b'Report File')),
                ('status', models.CharField(default=b'requested', max_length=10)),
                ('options', models.CharField(max_length=1000)),
                ('datetime', models.DateTimeField(auto_now_add=True)),
                ('done_datetime', models.DateTimeField(null=True)),
            ],
            options={
                'ordering': ['-datetime'],
            },
        ),
        migrations.CreateModel(
            name='Report_Type',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(max_length=300)),
            ],
        ),
        migrations.CreateModel(
            name='Risk_Acceptance',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('path', models.FileField(verbose_name=b'Risk Acceptance File', editable=False, upload_to=b'risk/%Y/%m/%d')),
                ('created', models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ('accepted_findings', models.ManyToManyField(to='dojo.Finding')),
                ('notes', models.ManyToManyField(to='dojo.Notes', editable=False)),
            ],
        ),
        migrations.CreateModel(
            name='Scan',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('date', models.DateTimeField(default=dojo.models.get_current_datetime, editable=False, blank=True)),
                ('protocol', models.CharField(default=b'TCP', max_length=10)),
                ('status', models.CharField(default=b'Pending', max_length=10, editable=False)),
                ('baseline', models.BooleanField(default=False, verbose_name=b'Current Baseline')),
            ],
        ),
        migrations.CreateModel(
            name='ScanSettings',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('addresses', models.TextField(default=b'none')),
                ('date', models.DateTimeField(default=dojo.models.get_current_datetime, editable=False, blank=True)),
                ('frequency', models.CharField(max_length=10000, null=True, blank=True)),
                ('email', models.CharField(max_length=512)),
                ('protocol', models.CharField(default=b'TCP', max_length=10)),
                ('product', models.ForeignKey(default=1, editable=False, to='dojo.Product')),
            ],
        ),
        migrations.CreateModel(
            name='Stub_Finding',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('title', models.TextField(max_length=1000)),
                ('date', models.DateField(default=dojo.models.get_current_date)),
                ('severity', models.CharField(max_length=200, null=True, blank=True)),
                ('description', models.TextField(null=True, blank=True)),
            ],
        ),
        migrations.CreateModel(
            name='Test',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('target_start', models.DateTimeField()),
                ('target_end', models.DateTimeField()),
                ('estimated_time', models.TimeField(null=True, editable=False, blank=True)),
                ('actual_time', models.TimeField(null=True, editable=False, blank=True)),
                ('percent_complete', models.IntegerField(null=True, blank=True)),
                ('engagement', models.ForeignKey(editable=False, to='dojo.Engagement')),
                ('environment', models.ForeignKey(to='dojo.Development_Environment', null=True)),
                ('notes', models.ManyToManyField(to='dojo.Notes', editable=False, blank=True)),
            ],
        ),
        migrations.CreateModel(
            name='Test_Type',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(max_length=200)),
            ],
        ),
        migrations.CreateModel(
            name='VA',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('address', models.TextField(default=b'none', editable=False)),
                ('status', models.BooleanField(default=False, editable=False)),
                ('start', models.CharField(max_length=100)),
                ('result', models.ForeignKey(blank=True, editable=False, to='dojo.Test', null=True)),
            ],
        ),
        migrations.CreateModel(
            name='Dojo_User',
            fields=[
            ],
            options={
                'proxy': True,
            },
            bases=('auth.user',),
            managers=[
                ('objects', django.contrib.auth.models.UserManager()),
            ],
        ),
        migrations.AddField(
            model_name='va',
            name='user',
            field=models.ForeignKey(editable=False, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='test',
            name='test_type',
            field=models.ForeignKey(to='dojo.Test_Type'),
        ),
        migrations.AddField(
            model_name='stub_finding',
            name='reporter',
            field=models.ForeignKey(editable=False, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='stub_finding',
            name='test',
            field=models.ForeignKey(editable=False, to='dojo.Test'),
        ),
        migrations.AddField(
            model_name='scansettings',
            name='user',
            field=models.ForeignKey(editable=False, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='scan',
            name='scan_settings',
            field=models.ForeignKey(default=1, editable=False, to='dojo.ScanSettings'),
        ),
        migrations.AddField(
            model_name='risk_acceptance',
            name='reporter',
            field=models.ForeignKey(editable=False, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='report',
            name='requester',
            field=models.ForeignKey(to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='product',
            name='authorized_users',
            field=models.ManyToManyField(to=settings.AUTH_USER_MODEL, blank=True),
        ),
        migrations.AddField(
            model_name='product',
            name='prod_type',
            field=models.ForeignKey(related_name='prod_type', blank=True, to='dojo.Product_Type', null=True),
        ),
        migrations.AddField(
            model_name='notes',
            name='author',
            field=models.ForeignKey(editable=False, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='ipscan',
            name='scan',
            field=models.ForeignKey(default=1, editable=False, to='dojo.Scan'),
        ),
        migrations.AddField(
            model_name='finding',
            name='last_reviewed_by',
            field=models.ForeignKey(related_name='last_reviewed_by', editable=False, to=settings.AUTH_USER_MODEL, null=True),
        ),
        migrations.AddField(
            model_name='finding',
            name='mitigated_by',
            field=models.ForeignKey(related_name='mitigated_by', editable=False, to=settings.AUTH_USER_MODEL, null=True),
        ),
        migrations.AddField(
            model_name='finding',
            name='notes',
            field=models.ManyToManyField(to='dojo.Notes', editable=False, blank=True),
        ),
        migrations.AddField(
            model_name='finding',
            name='reporter',
            field=models.ForeignKey(related_name='reporter', editable=False, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='finding',
            name='test',
            field=models.ForeignKey(editable=False, to='dojo.Test'),
        ),
        migrations.AddField(
            model_name='engagement',
            name='eng_type',
            field=models.ForeignKey(blank=True, to='dojo.Engagement_Type', null=True),
        ),
        migrations.AddField(
            model_name='engagement',
            name='lead',
            field=models.ForeignKey(to=settings.AUTH_USER_MODEL, null=True),
        ),
        migrations.AddField(
            model_name='engagement',
            name='product',
            field=models.ForeignKey(to='dojo.Product'),
        ),
        migrations.AddField(
            model_name='engagement',
            name='report_type',
            field=models.ForeignKey(blank=True, to='dojo.Report_Type', null=True),
        ),
        migrations.AddField(
            model_name='engagement',
            name='requester',
            field=models.ForeignKey(blank=True, to='dojo.Contact', null=True),
        ),
        migrations.AddField(
            model_name='engagement',
            name='risk_acceptance',
            field=models.ManyToManyField(default=None, to='dojo.Risk_Acceptance', editable=False, blank=True),
        ),
        migrations.AddField(
            model_name='endpoint',
            name='product',
            field=models.ForeignKey(blank=True, to='dojo.Product', null=True),
        ),
        migrations.AddField(
            model_name='check_list',
            name='auth_issues',
            field=models.ManyToManyField(related_name='auth_issues', to='dojo.Finding', blank=True),
        ),
        migrations.AddField(
            model_name='check_list',
            name='author_issues',
            field=models.ManyToManyField(related_name='author_issues', to='dojo.Finding', blank=True),
        ),
        migrations.AddField(
            model_name='check_list',
            name='config_issues',
            field=models.ManyToManyField(related_name='config_issues', to='dojo.Finding', blank=True),
        ),
        migrations.AddField(
            model_name='check_list',
            name='crypto_issues',
            field=models.ManyToManyField(related_name='crypto_issues', to='dojo.Finding', blank=True),
        ),
        migrations.AddField(
            model_name='check_list',
            name='data_issues',
            field=models.ManyToManyField(related_name='data_issues', to='dojo.Finding', blank=True),
        ),
        migrations.AddField(
            model_name='check_list',
            name='engagement',
            field=models.ForeignKey(related_name='eng_for_check', editable=False, to='dojo.Engagement'),
        ),
        migrations.AddField(
            model_name='check_list',
            name='other_issues',
            field=models.ManyToManyField(related_name='other_issues', to='dojo.Finding', blank=True),
        ),
        migrations.AddField(
            model_name='check_list',
            name='sensitive_issues',
            field=models.ManyToManyField(related_name='sensitive_issues', to='dojo.Finding', blank=True),
        ),
        migrations.AddField(
            model_name='check_list',
            name='session_issues',
            field=models.ManyToManyField(related_name='session_issues', to='dojo.Finding', blank=True),
        ),
        migrations.AddField(
            model_name='burprawrequestresponse',
            name='finding',
            field=models.ForeignKey(blank=True, to='dojo.Finding', null=True),
        ),
    ]
