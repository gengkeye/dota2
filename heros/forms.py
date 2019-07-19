# -*- coding: utf-8 -*-
#
from __future__ import unicode_literals

from django import forms
from django.utils.translation import gettext_lazy as _, gettext

from heros.models import Hero, Relationship

class HeroCreateForm(forms.ModelForm):
	class Meta:
		model = Hero
		fields = ['name', 'category']


class RelationshipCreateForm(forms.ModelForm):
	class Meta:
		model = Relationship
		fields = '__all__'