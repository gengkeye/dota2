# ~*~ coding: utf-8 ~*~
from __future__ import unicode_literals

from django.urls import path

from . import views

app_name = 'heros'

urlpatterns = [
    path('create', views.HeroCreateView.as_view(), name='create-hero'),
    path('<uuid:pk>/update', views.HeroCreateView.as_view(), name='update-hero'),
    path('relationship/create', views.RelationshipCreateView.as_view(), name='create-relationship'),
    path('relationship/<uuid:pk>/update', views.RelationshipCreateView.as_view(), name='update-relationship'),
]