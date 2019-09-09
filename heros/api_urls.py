# coding:utf-8
#

from rest_framework_bulk.routes import BulkRouter
from heros.api import HeroViewSet

app_name = 'heros'

router = BulkRouter()

router.register(r'heros', HeroViewSet, 'heros')

urlpatterns = []

urlpatterns += router.urls