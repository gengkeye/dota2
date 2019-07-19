# -*- coding: utf-8 -*-
#

from rest_framework import permissions

class ReadOnly(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True