# -*- coding: utf-8 -*-
#
import time

from rest_framework import permissions
from django.contrib.auth.mixins import UserPassesTestMixin
from django.shortcuts import redirect
from django.http.response import HttpResponseForbidden
from django.conf import settings


class IsValidUser(permissions.IsAuthenticated, permissions.BasePermission):
    """Allows access to valid user, is active and not expired"""

    def has_permission(self, request, view):
        return super().has_permission(request, view) \
            and request.user.is_valid


class IsAppUser(IsValidUser):
    """Allows access only to app user """

    def has_permission(self, request, view):
        return super().has_permission(request, view) \
            and request.user.is_app


class IsSuperUser(IsValidUser):
    def has_permission(self, request, view):
        return super().has_permission(request, view) \
               and request.user.is_superuser
               

class IsAdminUser(IsValidUser):
    def has_permission(self, request, view):
        return super().has_permission(request, view) \
               and request.user.is_admin


class IsSuperUserOrAppUser(IsValidUser):
    def has_permission(self, request, view):
        return super().has_permission(request, view) \
            and (request.user.is_superadmin or request.user.is_app)


class IsAdminUserOrAppUser(IsValidUser):
    """Allows access to superuser or group admin"""

    def has_permission(self, request, view):
        return super().has_permission(request, view) \
            and (request.user.is_admin or request.user.is_app)


class IsOrgAdmin(IsValidUser):
    """Allows access only to superuser"""

    def has_permission(self, request, view):
        return super().has_permission(request, view) \
            and request.user.is_admin


class IsOrgAdminOrAppUser(IsValidUser):
    """Allows access between superuser and app user"""

    def has_permission(self, request, view):
        return super().has_permission(request, view) \
            and (request.user.is_admin or request.user.is_app)


class IsOrgAdminOrAppUserOrUserReadonly(IsOrgAdminOrAppUser):
    def has_permission(self, request, view):
        if IsValidUser.has_permission(self, request, view) \
                and request.method in permissions.SAFE_METHODS:
            return True
        else:
            return IsOrgAdminOrAppUser.has_permission(self, request, view)


class IsCurrentUserOrReadOnly(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        return obj == request.user


class SuperUserRequiredMixin(UserPassesTestMixin):
    def test_func(self):
        if self.request.user.is_authenticated and self.request.user.is_superadmin:
            return True


class NavbarManagementMixin(UserPassesTestMixin):
    def test_func(self):
        user = self.request.user
        if not user.is_authenticated:
            return False
        elif not user.navbars.filter(href__startswith=self.request.resolver_match.view_name):
            self.raise_exception = True
            return False
        return True


class LoginRequiredMixin(UserPassesTestMixin):
    def test_func(self):
        if self.request.user.is_authenticated:
            return True
        else:
            return False


class AdminUserRequiredMixin(UserPassesTestMixin):
    def test_func(self):
        if not self.request.user.is_authenticated:
            return False
        elif not self.request.user.is_admin:
            self.raise_exception = True
            return False
        return True


class AdminOrGroupAdminRequiredMixin(UserPassesTestMixin):
    def test_func(self):
        usr = self.request.user
        if not usr.is_authenticated:
            return False
        elif not usr.is_admin:
            self.raise_exception = True
            return False
        return True


class ApplyUserRequiredMixin(UserPassesTestMixin):
    def test_func(self):
        if not self.request.user.is_authenticated:
            return False
        elif not self.request.user.is_applier:
            self.raise_exception = True
            return False
        return True


class IsAdminOrIsSelfRequiredMixin(UserPassesTestMixin):
    def test_func(self):
        current_user = self.request.user
        if current_user.is_authenticated and \
            current_user.is_superadmin or \
            current_user.is_commanuser:
            return True


class WithBootstrapToken(permissions.BasePermission):
    def has_permission(self, request, view):
        authorization = request.META.get('HTTP_AUTHORIZATION', '')
        if not authorization:
            return False
        request_bootstrap_token = authorization.split()[-1]
        return settings.BOOTSTRAP_TOKEN == request_bootstrap_token
