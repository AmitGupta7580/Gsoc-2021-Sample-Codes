from graphene import relay, Schema, ObjectType, List, Field, String
from graphene_django import DjangoObjectType
from graphene_django.filter import DjangoFilterConnectionField

from vulnerabilities.api import MinimalPackageSerializer, VulnerabilityReferenceSerializer, VulnerabilitySerializer

from vulnerabilities.models import Package
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilityReference
from vulnerabilities.models import VulnerabilitySeverity

from packageurl import PackageURL
from rest_framework.response import Response

class VulnerabilityReferenceType(DjangoObjectType):
    class Meta:
        model = VulnerabilityReference
        fields = "__all__"

class VulnerabilitySeverityType(DjangoObjectType):
	class  Meta:
		model = VulnerabilitySeverity
		fields = "__all__"

class VulnerabilityType(DjangoObjectType):
    class Meta:
        model = Vulnerability
        fields = "__all__"

class PackageType(DjangoObjectType):
    class Meta:
        model = Package
        filter_fields = ['name'] # other filter options
        interfaces = (relay.Node, )

class PackageUrlType(DjangoObjectType):
	class Meta:
		model = Package
		fields = "__all__"

class Query(ObjectType):
    vulnerabilities = List(VulnerabilityType)
    packages = DjangoFilterConnectionField(PackageType)
    vulnerability_reference = List(VulnerabilityReferenceType)
    vulnerability_severity = List(VulnerabilitySeverityType)
    packages_url = Field(lambda: List(PackageUrlType), purls=List(String))

    def resolve_packages_url(root, info, purls):
    	queryset = Package.objects.none()
    	for purl in purls:
    		try:
       			purl = PackageURL.from_string(purl).to_dict()
       			data = Package.objects.filter(**{key: value for key, value in purl.items() if value})
    		except ValueError as ve:
    			data = Package.objects.none()
    		queryset = queryset | data
    	return queryset

schema = Schema(query=Query)