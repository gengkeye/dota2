# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib import admin
from django.urls import include, path
from heros.views import HeroListView
from django.views.i18n import JavaScriptCatalog
from django.conf.urls.i18n import i18n_patterns
from django.conf import settings
from django.conf.urls.static import static



urlpatterns = [
    path('', HeroListView.as_view(), name='index'),
    path('heros/', include('heros.urls', namespace='heros')),
    path('heros/v1/', include('heros.api_urls', namespace='api-heros')),
    path('admin/', admin.site.urls),
]

js_i18n_patterns = i18n_patterns(
    path('jsi18n/', JavaScriptCatalog.as_view(), name='javascript-catalog'),
)

urlpatterns += js_i18n_patterns

urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT) \
            + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)