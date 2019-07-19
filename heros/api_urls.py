# coding:utf-8
#

from rest_framework_bulk.routes import BulkRouter
from heros.api import UserViewSet

app_name = 'heros'

router = BulkRouter()

router.register(r'heros', UserViewSet, 'heros')

urlpatterns = []

urlpatterns += router.urls