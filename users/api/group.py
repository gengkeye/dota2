# -*- coding: utf-8 -*-
#

from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework_bulk import BulkModelViewSet
from rest_framework.pagination import LimitOffsetPagination

from ..serializers import UserGroupSerializer, \
    UserGroupUpdateMemberSerializer
from ..models import UserGroup, User
from common.permissions import IsOrgAdmin
from common.mixins import IDInCacheFilterMixin


__all__ = ['UserGroupViewSet', 'UserGroupUpdateUserApi']


class UserGroupViewSet(IDInCacheFilterMixin, BulkModelViewSet):
    filter_fields = ("name",)
    search_fields = filter_fields
    queryset = UserGroup.objects.all()
    serializer_class = UserGroupSerializer
    permission_classes = (IsOrgAdmin,)
    pagination_class = LimitOffsetPagination

    def perform_update(self, serializer):
        obj = self.get_object()
        users_id_list = self.request.data['users']
        obj.users.set(User.objects.filter(id__in=users_id_list))

        if self.request.user.is_superadmin:
            managers_id_list = self.request.data['managers']
            obj.managers.set(User.objects.filter(id__in=managers_id_list))

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if self.request.user.is_superadmin:
            managers_id_list = self.request.data['managers_id']
            serializer.validated_data['managers'] = (User.objects.filter(id__in=managers_id_list))
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class UserGroupUpdateUserApi(generics.RetrieveUpdateAPIView):
    queryset = UserGroup.objects.all()
    serializer_class = UserGroupUpdateMemberSerializer
    permission_classes = (IsOrgAdmin,)
