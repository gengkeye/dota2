# -*- coding: utf-8 -*-
#
from __future__ import unicode_literals

from rest_framework import serializers
from heros.models import Hero


class HeroSerializer(serializers.ModelSerializer):
    dads_display = serializers.SerializerMethodField(required=False)
    sons_display = serializers.SerializerMethodField(required=False)

    class Meta:
        model = Hero
        fields = '__all__'

    @staticmethod
    def get_dads_display(obj):
        return ','.join(obj.dads.values_list('name', flat=True))

    @staticmethod 
    def get_sons_display(obj):
        return ','.join(obj.sons.values_list('name', flat=True))