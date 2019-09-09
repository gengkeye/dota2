# ~*~ coding: utf-8 ~*~

from rest_framework_bulk import BulkModelViewSet
from heros.serializers import HeroSerializer
from common.permissions import ReadOnly

class HeroViewSet(BulkModelViewSet):
	filter_fields = ('name',)
	search_fields = filter_fields
	serializer_class = HeroSerializer
	permission_classes = (ReadOnly,)