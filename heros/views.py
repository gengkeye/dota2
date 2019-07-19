# ~*~ coding: utf-8 ~*~
from __future__ import unicode_literals

from django.http import HttpResponse
from django.views.generic import TemplateView
from django.views.generic.edit import CreateView, UpdateView
from django.urls import reverse_lazy
from django.utils.translation import gettext as _



from heros.models import Hero, Relationship
from heros import forms
from .serializers import HeroSerializer

class HeroListView(TemplateView):
    template_name = 'hero_list.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        heros = Hero.objects.all()
        serializer = HeroSerializer(heros, many=True)
        context.update({
            'app': _('Users'),
            'querysets': serializer.data,
        })
        return context


class HeroCreateView(CreateView):
    template_name = 'hero_create.html'
    model = Hero
    success_url = reverse_lazy('heros:create-hero')

class HeroUpdateView(UpdateView):
    template_name = 'hero_update.html'
    model = Hero
    success_url = reverse_lazy('heros:update-hero')


class RelationshipCreateView(CreateView):
    template_name = 'hero_create.html'
    model = Relationship
    success_url = reverse_lazy('relationships:create-relationship')


class RelationshipUpdateView(UpdateView):
    template_name = 'relationship_update.html'
    model = Relationship
    success_url = reverse_lazy('relationships:update-relationship') 