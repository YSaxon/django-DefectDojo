# see tastypie documentation at http://django-tastypie.readthedocs.org/en
from tastypie import fields
from tastypie.authentication import ApiKeyAuthentication, MultiAuthentication, SessionAuthentication
from tastypie.authorization import Authorization
from tastypie.authorization import DjangoAuthorization
from tastypie.constants import ALL, ALL_WITH_RELATIONS
from tastypie.exceptions import Unauthorized
from tastypie.resources import ModelResource,Resource
from tastypie.serializers import Serializer
from tastypie.validation import CleanedDataFormValidation
from tastypie import utils
#from tastypie.resources import Resource

from dojo.models import Product, Engagement, Test, Finding, \
    User, ScanSettings, IPScan, Scan, Stub_Finding, Risk_Acceptance,FileUpload
from dojo.forms import ProductForm, EngForm2, TestForm, \
    ScanSettingsForm, FindingForm, StubFindingForm

"""
    Setup logging for the api

logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)d] %(message)s',
    datefmt='%d/%b/%Y %H:%M:%S',
    filename=settings.DOJO_ROOT + '/../dojo.log',
)
logger = logging.getLogger(__name__)
"""


class BaseModelResource(ModelResource):
    @classmethod
    def get_fields(cls, fields=None, excludes=None):
        """
         Unfortunately we must override this method because tastypie ignores
         'blank' attribute on model fields.

         Here we invoke an insane workaround hack due to metaclass inheritance
         issues:
          http://stackoverflow.com/questions/12757468/invoking-super-in-classmethod-called-from-metaclass-new
        """
        this_class = next(
            c for c in cls.__mro__
            if c.__module__ == __name__ and c.__name__ == 'BaseModelResource')
        fields = super(this_class, cls).get_fields(fields=fields,
                                                   excludes=excludes)
        if not cls._meta.object_class:
            return fields
        for django_field in cls._meta.object_class._meta.fields:
            if django_field.blank is True:
                res_field = fields.get(django_field.name, None)
                if res_field:
                    res_field.blank = True
        return fields


# Authentication class - this only allows for header auth, no url parms allowed
# like parent class.


class DojoApiKeyAuthentication(ApiKeyAuthentication):
    def extract_credentials(self, request):
        if (request.META.get('HTTP_AUTHORIZATION') and
                request.META['HTTP_AUTHORIZATION'].lower().startswith('apikey ')):
            (auth_type, data) = request.META['HTTP_AUTHORIZATION'].split()

            if auth_type.lower() != 'apikey':
                raise ValueError("Incorrect authorization header.")

            username, api_key = data.split(':', 1)
        else:
            raise ValueError("Incorrect authorization header.")

        return username, api_key


# Authorization class for Product
class UserProductsOnlyAuthorization(Authorization):
    def read_list(self, object_list, bundle):
        # This assumes a ``QuerySet`` from ``ModelResource``.
        if bundle.request.user.is_staff:
            return object_list
        return object_list.filter(authorized_users__in=[bundle.request.user])

    def read_detail(self, object_list, bundle):
        # Is the requested object owned by the user?
        return (bundle.request.user.is_staff or
                bundle.request.user in bundle.obj.authorized_users)

    def create_list(self, object_list, bundle):
        # Assuming they're auto-assigned to ``user``.
        return object_list.filter(authorized_users__in=[bundle.request.user])

    def create_detail(self, object_list, bundle):
        return (bundle.request.user.is_staff or
                bundle.request.user in bundle.obj.authorized_users)

    def update_list(self, object_list, bundle):
        allowed = []

        # Since they may not all be saved, iterate over them.
        for obj in object_list:
            if (bundle.request.user.is_staff or
                        bundle.request.user in bundle.obj.authorized_users):
                allowed.append(obj)

        return allowed

    def update_detail(self, object_list, bundle):
        return (bundle.request.user.is_staff or
                bundle.request.user in bundle.obj.authorized_users)

    def delete_list(self, object_list, bundle):
        # Sorry user, no deletes for you!
        raise Unauthorized("Sorry, no deletes.")

    def delete_detail(self, object_list, bundle):
        raise Unauthorized("Sorry, no deletes.")


# Authorization class for Scan Settings
class UserScanSettingsAuthorization(Authorization):
    def read_list(self, object_list, bundle):
        # This assumes a ``QuerySet`` from ``ModelResource``.
        if bundle.request.user.is_staff:
            return object_list

        return object_list.filter(product__authorized_users__in=[
            bundle.request.user])

    def read_detail(self, object_list, bundle):
        # Is the requested object owned by the user?
        return (bundle.request.user.is_staff or
                bundle.request.user in bundle.obj.product.authorized_users)

    def create_list(self, object_list, bundle):
        # Assuming they're auto-assigned to ``user``.
        if bundle.request.user.is_staff:
            return object_list
        else:
            return object_list.filter(
                product__authorized_users__in=[bundle.request.user])

    def create_detail(self, object_list, bundle):
        return (bundle.request.user.is_staff or
                bundle.request.user in bundle.obj.product.authorized_users)

    def update_list(self, object_list, bundle):
        allowed = []

        # Since they may not all be saved, iterate over them.
        for obj in object_list:
            if (bundle.request.user.is_staff or
                        bundle.request.user in
                        bundle.obj.product.authorized_users):
                allowed.append(obj)

        return allowed

    def update_detail(self, object_list, bundle):
        return (bundle.request.user.is_staff or
                bundle.request.user in bundle.obj.product.authorized_users)

    def delete_list(self, object_list, bundle):
        return (bundle.request.user.is_staff or
                bundle.request.user in bundle.obj.product.authorized_users)

    def delete_detail(self, object_list, bundle):
        return (bundle.request.user.is_staff or
                bundle.request.user in bundle.obj.product.authorized_users)


# Authorization class for Scan Settings
class UserScanAuthorization(Authorization):
    def read_list(self, object_list, bundle):
        # This assumes a ``QuerySet`` from ``ModelResource``.
        if bundle.request.user.is_staff:
            return object_list

        return object_list.filter(
            scan_settings__product__authorized_users__in=[
                bundle.request.user])

    def read_detail(self, object_list, bundle):
        # Is the requested object owned by the user?
        return (bundle.request.user.is_staff or
                bundle.request.user in
                bundle.obj.scan_settings.product.authorized_users)

    def create_list(self, object_list, bundle):
        # Assuming they're auto-assigned to ``user``.
        if bundle.request.user.is_staff:
            return object_list
        else:
            return object_list.filter(
                scan_settings__product__authorized_users__in=[
                    bundle.request.user])

    def create_detail(self, object_list, bundle):
        return (bundle.request.user.is_staff or
                bundle.request.user in
                bundle.obj.scan_settings.product.authorized_users)

    def update_list(self, object_list, bundle):
        allowed = []

        # Since they may not all be saved, iterate over them.
        for obj in object_list:
            if (bundle.request.user.is_staff or
                        bundle.request.user in
                        bundle.obj.scan_settings.product.authorized_users):
                allowed.append(obj)

        return allowed

    def update_detail(self, object_list, bundle):
        return (bundle.request.user.is_staff or
                bundle.request.user in
                bundle.obj.scan_settings.product.authorized_users)

    def delete_list(self, object_list, bundle):
        return (bundle.request.user.is_staff or
                bundle.request.user in
                bundle.obj.scan_settings.product.authorized_users)

    def delete_detail(self, object_list, bundle):
        return (bundle.request.user.is_staff or
                bundle.request.user in
                bundle.obj.scan_settings.product.authorized_users)


"""
  Look up resource only, no update, store, delete
"""


class UserResource(BaseModelResource):
    class Meta:
        queryset = User.objects.all()
        resource_name = 'users'
        fields = ['id', 'username', 'first_name', 'last_name', 'last_login']

        list_allowed_methods = ['get']
        detail_allowed_methods = ['get']
        include_resource_uri = True
        filtering = {
            'id': ALL,
            'username': ALL,
            'first_name': ALL,
            'last_name': ALL
        }
        authorization = DjangoAuthorization()
        authentication = DojoApiKeyAuthentication()
        serializer = Serializer(formats=['json'])


"""
    POST, PUT
    Expects *product name, *description, *prod_type [1-7]
"""


class ProductResource(BaseModelResource):
    class Meta:
        resource_name = 'products'
        # disabled delete. Should not be allowed without fine authorization.
        list_allowed_methods = ['get', 'post']  # only allow get for lists
        detail_allowed_methods = ['get', 'post', 'put']
        queryset = Product.objects.all().order_by('name')
        ordering = ['name', 'id', 'description', 'findings_count', 'created',
                    'product_type_id']
        excludes = ['tid', 'manager', 'prod_manager', 'tech_contact',
                    'updated']
        include_resource_uri = True
        filtering = {
            'id': ALL,
            'name': ALL,
            'prod_type': ALL,
            'created': ALL,
            'findings_count': ALL
        }
        authentication = DojoApiKeyAuthentication()
        authorization = UserProductsOnlyAuthorization()
        serializer = Serializer(formats=['json'])
        validation = CleanedDataFormValidation(form_class=ProductForm)

    def dehydrate(self, bundle):
        try:
            bundle.data['prod_type'] = bundle.obj.prod_type
        except:
            bundle.data['prod_type'] = 'unknown'
        bundle.data['findings_count'] = bundle.obj.findings_count
        return bundle


"""
    POST, PUT [/id/]
    Expects *product *target_start, *target_end, *status[In Progress, On Hold,
    Completed], threat_model, pen_test, api_test, check_list
"""


class EngagementResource(BaseModelResource):
    product = fields.ForeignKey(ProductResource, 'product',
                                full=False, null=False)
    lead = fields.ForeignKey(UserResource, 'lead',
                             full=False, null=True)

    class Meta:
        resource_name = 'engagements'
        list_allowed_methods = ['get', 'post']
        # disabled delete for /id/
        detail_allowed_methods = ['get', 'post', 'put']
        queryset = Engagement.objects.all()
        include_resource_uri = True
        filtering = {
            'id': ALL,
            'active': ALL,
            'eng_type': ALL,
            'target_start': ALL,
            'target_end': ALL,
            'requester': ALL,
            'report_type': ALL,
            'updated': ALL,
            'threat_model': ALL,
            'api_test': ALL,
            'pen_test': ALL,
            'status': ALL,
            'product': ALL,
        }
        authentication = DojoApiKeyAuthentication()
        authorization = DjangoAuthorization()
        serializer = Serializer(formats=['json'])
        validation = CleanedDataFormValidation(form_class=EngForm2)

    def dehydrate(self, bundle):
        if bundle.obj.eng_type is not None:
            bundle.data['eng_type'] = bundle.obj.eng_type.name
        else:
            bundle.data['eng_type'] = None
        bundle.data['product_id'] = bundle.obj.product.id
        bundle.data['report_type'] = bundle.obj.report_type
        bundle.data['requester'] = bundle.obj.requester
        return bundle


"""
    /api/v1/tests/
    GET [/id/], DELETE [/id/]
    Expects: no params or engagement_id
    Returns test: ALL or by engagement_id
    Relevant apply filter ?test_type=?, ?id=?

    POST, PUT [/id/]
    Expects *test_type, *engagement, *target_start, *target_end,
    estimated_time, actual_time, percent_complete, notes
"""


class TestResource(BaseModelResource):
    engagement = fields.ForeignKey(EngagementResource, 'engagement',
                                   full=False, null=False)

    class Meta:
        resource_name = 'tests'
        list_allowed_methods = ['get', 'post']
        # disabled delete. Should not be allowed without fine authorization.
        detail_allowed_methods = ['get', 'post', 'put']
        queryset = Test.objects.all().order_by('target_end')
        include_resource_uri = True
        filtering = {
            'id': ALL,
            'test_type': ALL,
            'target_start': ALL,
            'target_end': ALL,
            'notes': ALL,
            'percent_complete': ALL,
            'actual_time': ALL,
            'engagement': ALL,
        }
        authentication = DojoApiKeyAuthentication()
        authorization = DjangoAuthorization()
        serializer = Serializer(formats=['json'])
        validation = CleanedDataFormValidation(form_class=TestForm)

    def dehydrate(self, bundle):
        bundle.data['test_type'] = bundle.obj.test_type
        return bundle

"""
		TODO change url and make sure it's registered
    /api/v1/tests/
    GET [/id/], DELETE [/id/]
    Expects: no params or engagement_id
    Returns test: ALL or by engagement_id
    Relevant apply filter ?test_type=?, ?id=?

    POST, PUT [/id/]
    Expects *test_type, *engagement, *target_start, *target_end,
    estimated_time, actual_time, percent_complete, notes
"""


'''class ScanUploadResource(BaseModelResource):
    engagement = fields.ForeignKey(EngagementResource, 'engagement',
                                   full=False, null=False)

    class Meta:
        resource_name = 'tests'#change this to scanimport?
        list_allowed_methods = ['get', 'post']
        # disabled delete. Should not be allowed without fine authorization.
        detail_allowed_methods = ['get', 'post', 'put']
        queryset = Test.objects.all().order_by('target_end')
        include_resource_uri = True
        filtering = {
            'id': ALL,
            'test_type': ALL,
            'target_start': ALL,
            'target_end': ALL,
            'notes': ALL,
            'percent_complete': ALL,
            'actual_time': ALL,
            'engagement': ALL,
        }
        authentication = DojoApiKeyAuthentication()
        authorization = DjangoAuthorization()
        serializer = Serializer(formats=['json'])
        validation = CleanedDataFormValidation(form_class=TestForm)

    def dehydrate(self, bundle):
        bundle.data['test_type'] = bundle.obj.test_type
        return bundle
'''

def upload_view(request):
    from django.http import HttpResponse
    print "uploadview1"
    if request.method != 'POST':
        return HttpResponse("notpost")
        #return http.HttpResponseBadRequest()
        
    print "uploadview2"
    #resource = resources.UploadedFileResource()

    # TODO: Provide some user feedback while uploading
    filename="none"
    uploaded_files = []
    for field, files in request.FILES.iterlists():
        print "uploadview3"
        for file in files:
            # We let storage decide a name
            import os,binascii
            filename=binascii.b2a_hex(os.urandom(15))
            print filename
            fileobject = storage.default_storage.save(filename, file)
            uploaded_files.append(filename)
            '''
            uploaded_file = api_models.UploadedFile()
            uploaded_file.author = request.user
            uploaded_file.filename = filename
            uploaded_file.content_type = file.content_type
            uploaded_file.save()
            uploaded_files.append({
                'filename': filename,
                'resource_uri': resource.get_resource_uri(uploaded_file)
            })'''
    # TODO: Create background task to process uploaded file (check content type (both in GridFS file and UploadedFile document), resize images)

    return HttpResponse(filename)#resource.create_response(request, uploaded_files, response_class=tastypie_http.HttpAccepted)

class MultipartResource(object):
    def deserialize(self, request, data, format=None):
        print "0!"
        if not format:
            format = request.META.get('CONTENT_TYPE', 'application/json')
            print "1!"
        if format == 'application/x-www-form-urlencoded':
            print "2!"
            return request.POST
        if format.startswith('multipart'):
            print "3!"
            data = request.POST.copy()
            data.update(request.FILES)
            return data
        return super(MultipartResource, self).deserialize(request, data, format)
    
import base64
import os
from tastypie.fields import FileField
from django.core.files.uploadedfile import SimpleUploadedFile
import mimetypes


class ThreatUploadResource(Resource):#MultipartResource,
    #file = Base64FileField("file")
    #date = DateField("date")
    print "threatuploadbeforemeta"
    class Meta:
        resource_name = 'threat_upload'
        list_allowed_methods = ['post']
        detail_allowed_methods = []
        authentication = DojoApiKeyAuthentication()
        authorization = DjangoAuthorization()
        #file_field = Base64FileField("file")
        #print file_field
        #print "success"
        #queryset = FileUpload.objects.all()
        #print request
    def obj_create(self, bundle, **kwargs):
        from pprint import pprint
        pprint (vars(bundle))
        value = bundle.data['file']
        id = bundle.data['id']
        file = SimpleUploadedFile(value["name"], base64.b64decode(value["file"]), getattr(value, "content_type", "application/octet-stream"))
        #print file
        from dojo.utils import handle_uploaded_threat
        handle_uploaded_threat(file,Engagement.objects.get(id=id))
        #print bundle['data']
        #pprint (vars(bundle.data))
        #SimpleUploadedFile(value["name"], base64.b64decode(value["file"]), getattr(value, "content_type", "application/octet-stream"))
        #from dojo.utils import handle_uploaded_threat
        #handle_uploaded_threat(bundle,Engagement.objects.get(id=1))


class Base64FileField(FileField):
    """
    A django-tastypie field for handling file-uploads through raw post data.
    It uses base64 for en-/decoding the contents of the file.
    Usage:
    class MyResource(ModelResource):
        file_field = Base64FileField("file_field")
        
        class Meta:
            queryset = ModelWithFileField.objects.all()
    In the case of multipart for submission, it would also pass the filename.
    By using a raw post data stream, we have to pass the filename within our
    file_field structure:
    file_field = {
        "name": "myfile.png",
        "file": "longbas64encodedstring",
        "content_type": "image/png" # on hydrate optional
    }
    """
    def dehydrate(self, bundle, for_list):
        if not bundle.data.has_key(self.instance_name) and hasattr(bundle.obj, self.instance_name):
            file_field = getattr(bundle.obj, self.instance_name)
            if file_field:
                try:
                    content_type, encoding = mimetypes.guess_type(file_field.file.name)
                    b64 = open(file_field.file.name, "rb").read().encode("base64")
                    ret = {
                        "name": os.path.basename(file_field.file.name),
                        "file": b64,
                        "content-type": content_type or "application/octet-stream"
                    }
                    return ret
                except:
                    pass
        return None

    def hydrate(self, obj):
        print "hydrate"
        value = super(FileField, self).hydrate(obj)
        if value:
            print "value"
            value = SimpleUploadedFile(value["name"], base64.b64decode(value["file"]), getattr(value, "content_type", "application/octet-stream"))
            from pprint import pprint
            #pprint (vars(value))
            from dojo.utils import handle_uploaded_threat
            #handle_uploaded_threat(value,Engagement.objects.get(id=1))
            #pprint (vars(value.file))
            #pprint (vars(value['file']))
            #mport IPython; IPython.embed()
        return value



from dojo.forms import ImportScanForm
from dojo.forms import SEVERITY_CHOICES
from django.shortcuts import render, get_object_or_404
from dojo.engagement.views import import_scan_results_logic
class ScanUploadResource(Resource):#MultipartResource,
    #file = Base64FileField(attribute="file",help_text="""A JSON like file_field = {
    #    "name": "myfile.png",
    #    "file": "longbas64encodedstring",
    #    "content_type": "image/png" # on hydrate optional
    #}""",blank=False,default="BLAH")
    eid= fields.IntegerField(attribute="eid",help_text="id of the engagement this scan is to be added to")#,blank=False)
    file = fields.FileField(attribute="file",help_text="a base64 encoded string of the file to be uploaded")#,blank=False)
    tags = fields.CharField(attribute="tags",help_text="a list of tags seperated by commas")#,default="testtag",blank=True)
    verified= fields.BooleanField(attribute="verified",help_text="Select if these findings findings have been verified.",blank=True)
    active= fields.BooleanField(attribute="active",help_text="Select if these findings are currently active.",blank=True)
    scan_date = fields.DateField(attribute="scan_date", help_text="Scan completion date will be used on all findings.")#,blank=False)#default=dojo.models.get_current_date)
    scan_type = fields.CharField(attribute="scan_type",help_text="scan type, one of: %s" % ', '.join(['%s (%s)' % (t[0], t[1]) for t in ImportScanForm.SCAN_TYPE_CHOICES]))
    minimum_severity= fields.CharField(attribute="minimum_severity",help_text="minimum severity level to upload, one of: %s" % ', '.join(['%s (%s)' % (t[0], t[1]) for t in SEVERITY_CHOICES]))
    print "scanuploadbeforemeta"
    class Meta:
        resource_name = 'scan_upload'
        list_allowed_methods = ['post']
        detail_allowed_methods = []
        authentication = DojoApiKeyAuthentication()
        authorization = DjangoAuthorization()
        #file_field = Base64FileField("file")
        #print file_field
        #print "success"
        #queryset = FileUpload.objects.all()
        #print request
    def obj_create(self, bundle, **kwargs):
        from pprint import pprint
        #pprint (vars(bundle))
        
        #id = bundle.data['id']
        #value = bundle.data['file']
        #file = SimpleUploadedFile(value["name"], base64.b64decode(value["file"]), getattr(value, "content_type", "application/octet-stream"))
        
        dictToPass=bundle.data
        if not 'tags' in dictToPass: dictToPass['tags']="notags-defaultval"
        if not 'verified' in dictToPass: dictToPass['verified']=False
        if not 'active' in dictToPass: dictToPass['active']=False
        if not 'minimum_severity' in dictToPass: dictToPass['minimum_severity']="Info"
        if not 'eid ' in dictToPass: raise Http404()
        if not 'scan_type ' in dictToPass: raise Http404()
        #if not 'scan_date' in dictToPass:dictToPass['scan_date']=
        dictToPass['file'] = SimpleUploadedFile("scanfile", base64.b64decode(bundle.data['file']), "application/octet-stream")
        dictToPass['request']=bundle.request
        import_scan_results_logic(dictToPass)
        #engagement = get_object_or_404(Engagement, id=bundle.data['eid'])
        #if not any(scan_type in code for code in ImportScanForm.SCAN_TYPE_CHOICES):
        

        
        

'''class ThreatUploadResource(BaseModelResource):
    class Meta:
        resource_name = 'threat_upload'
        allowed_methods = ['get']
        #detail_allowed_methods = ['get','post','put']
        queryset = Engagement.objects.all().filter(threat_model=True)#.values('tmodel_path')
        fields=['tmodel_path']
'''

class RiskAcceptanceResource(BaseModelResource):
    class Meta:
        resource_name = 'risk_acceptances'
        list_allowed_methods = ['get']
        detail_allowed_methods = ['get']
        queryset = Risk_Acceptance.objects.all().order_by('created')


"""
    /api/v1/findings/
    GET [/id/], DELETE [/id/]
    Expects: no params or test_id
    Returns test: ALL or by test_id
    Relevant apply filter ?active=True, ?id=?, ?severity=?

    POST, PUT [/id/]
    Expects *title, *date, *severity, *description, *mitigation, *impact,
    *endpoint, *test, cwe, active, false_p, verified,
    mitigated, *reporter

"""


class FindingResource(BaseModelResource):
    reporter = fields.ForeignKey(UserResource, 'reporter', null=False)
    test = fields.ForeignKey(TestResource, 'test', null=False)
    risk_acceptance = fields.ManyToManyField(RiskAcceptanceResource, 'risk_acceptance', null=True)
    product = fields.ForeignKey(ProductResource, 'test__engagement__product', full=False, null=False)
    engagement = fields.ForeignKey(EngagementResource, 'test__engagement', full=False, null=False)

    class Meta:
        resource_name = 'findings'
        queryset = Finding.objects.select_related("test")
        # deleting of findings is not allowed via UI or API.
        # Admin interface can be used for this.
        list_allowed_methods = ['get', 'post']
        detail_allowed_methods = ['get', 'post', 'put']
        include_resource_uri = True
        filtering = {
            'id': ALL,
            'title': ALL,
            'date': ALL,
            'severity': ALL,
            'description': ALL,
            'mitigated': ALL,
            'endpoint': ALL,
            'test': ALL_WITH_RELATIONS,
            'active': ALL,
            'verified': ALL,
            'false_p': ALL,
            'reporter': ALL,
            'url': ALL,
            'out_of_scope': ALL,
            'duplicate': ALL,
            'risk_acceptance': ALL,
            'engagement': ALL_WITH_RELATIONS,
            'product': ALL_WITH_RELATIONS
        }
        authentication = DojoApiKeyAuthentication()
        authorization = DjangoAuthorization()
        serializer = Serializer(formats=['json'])
        validation = CleanedDataFormValidation(form_class=FindingForm)

    def dehydrate(self, bundle):
        engagement = Engagement.objects.select_related('product'). \
            filter(test__finding__id=bundle.obj.id)
        bundle.data['engagement'] = "/api/v1/engagements/%s/" % engagement[0].id
        bundle.data['product'] = \
            "/api/v1/products/%s/" % engagement[0].product.id
        return bundle


class StubFindingResource(BaseModelResource):
    reporter = fields.ForeignKey(UserResource, 'reporter', null=False)
    test = fields.ForeignKey(TestResource, 'test', null=False)

    class Meta:
        resource_name = 'stub_findings'
        queryset = Stub_Finding.objects.select_related("test")
        # deleting of findings is not allowed via UI or API.
        # Admin interface can be used for this.
        list_allowed_methods = ['get', 'post']
        detail_allowed_methods = ['get', 'post', 'put']
        include_resource_uri = True
        filtering = {
            'id': ALL,
            'title': ALL,
            'date': ALL,
            'severity': ALL,
            'description': ALL,
        }

        authentication = DojoApiKeyAuthentication()
        authorization = DjangoAuthorization()
        serializer = Serializer(formats=['json'])
        validation = CleanedDataFormValidation(form_class=StubFindingForm)

    def dehydrate(self, bundle):
        engagement = Engagement.objects.select_related('product'). \
            filter(test__stub_finding__id=bundle.obj.id)
        bundle.data['engagement'] = "/api/v1/engagements/%s/" % engagement[0].id
        bundle.data['product'] = \
            "/api/v1/products/%s/" % engagement[0].product.id
        return bundle


'''
    /api/v1/scansettings/
    GET [/id/], DELETE [/id/]
    Expects: no params or product_id
    Returns test: ALL or by product_id

    POST, PUT [/id/]
    Expects *addresses, *user, *date, *frequency, *email, *product
'''


class ScanSettingsResource(BaseModelResource):
    user = fields.ForeignKey(UserResource, 'user', null=False)
    product = fields.ForeignKey(ProductResource, 'product', null=False)

    class Meta:
        resource_name = 'scan_settings'
        queryset = ScanSettings.objects.all()

        list_allowed_methods = ['get', 'post']
        detail_allowed_methods = ['get', 'put', 'post', 'delete']
        include_resource_uri = True
        filtering = {
            'id': ALL,
            'date': ALL,
            'user': ALL,
            'frequency': ALL,
            'product': ALL,
            'addresses': ALL
        }

        authentication = DojoApiKeyAuthentication()
        authorization = UserScanSettingsAuthorization()
        serializer = Serializer(formats=['json'])
        validation = CleanedDataFormValidation(form_class=ScanSettingsForm)


"""
    /api/v1/ipscans/
    Not exposed via API - but used as part of
    ScanResource return values
"""


class IPScanResource(BaseModelResource):
    class Meta:
        resource_name = 'ipscans'
        queryset = IPScan.objects.all()

        list_allowed_methods = ['get']
        detail_allowed_methods = ['get']
        include_resource_uri = True
        filtering = {
            'id': ALL,
            'address': ALL,
            'services': ALL,
            'scan': ALL
        }

        authentication = DojoApiKeyAuthentication()
        authorization = DjangoAuthorization()
        serializer = Serializer(formats=['json'])


"""
    /api/v1/scans/
    GET [/id/], DELETE [/id/]
    Expects: no params
    Returns scans: ALL
    Relevant filters: ?scan_setting=?
"""


class ScanResource(BaseModelResource):
    scan_settings = fields.ForeignKey(ScanSettingsResource,
                                      'scan_settings',
                                      null=False)
    ipscans = fields.ToManyField(
        IPScanResource,
        attribute=lambda bundle: IPScan.objects.filter(
            scan__id=bundle.obj.id) if IPScan.objects.filter(
            scan__id=bundle.obj.id) != [] else [], full=True, null=True)

    class Meta:
        resource_name = 'scans'
        queryset = Scan.objects.all()

        list_allowed_methods = ['get']
        detail_allowed_methods = ['get']
        include_resource_uri = True
        filtering = {
            'id': ALL,
            'date': ALL,
            'scan_settings': ALL
        }

        authentication = DojoApiKeyAuthentication()
        authorization = UserScanAuthorization()
        serializer = Serializer(formats=['json'])
