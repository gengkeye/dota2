# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib import admin
from django.urls import include, path
from heros.views import HeroListView
from .views import I18NView
from django.views.i18n import JavaScriptCatalog
from django.conf.urls.i18n import i18n_patterns
from django.conf import settings
from django.conf.urls.static import static


api_v1 = [
   path('authentication/v1/', include('authentication.urls.api_urls', namespace='api-auth')),
   path('heros/v1/', include('heros.api_urls', namespace='api-heros')),
]

api_v1_patterns = [
    path('api/', include(api_v1))
]


app_view_patterns = [
    path('heros/', include('heros.urls', namespace='heros')),
    path('auth/', include('authentication.urls.view_urls'), name='auth'),
]

urlpatterns = [
    path('', HeroListView.as_view(), name='index'),
    path('', include(api_v1_patterns)),
    path('', include(app_view_patterns)),
    path('i18n/<str:lang>/', I18NView.as_view(), name='i18n-switch'),
    path('admin/', admin.site.urls),
]

js_i18n_patterns = i18n_patterns(
    path('jsi18n/', JavaScriptCatalog.as_view(), name='javascript-catalog'),
)

handler404 = 'dota2.error_views.handler404'
handler500 = 'dota2.error_views.handler500'

urlpatterns += js_i18n_patterns

urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT) \
            + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

if settings.DEBUG:
    urlpatterns += [
        re_path('^swagger(?P<format>\.json|\.yaml)$',
                get_swagger_view().without_ui(cache_timeout=1), name='schema-json'),
        path('docs/', get_swagger_view().with_ui('swagger', cache_timeout=1), name="docs"),
        path('redoc/', get_swagger_view().with_ui('redoc', cache_timeout=1), name='redoc'),

        re_path('^v2/swagger(?P<format>\.json|\.yaml)$',
                get_swagger_view().without_ui(cache_timeout=1), name='schema-json'),
        path('docs/v2/', get_swagger_view("v2").with_ui('swagger', cache_timeout=1), name="docs"),
        path('redoc/v2/', get_swagger_view("v2").with_ui('redoc', cache_timeout=1), name='redoc'),
    ]