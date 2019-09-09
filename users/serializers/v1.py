# -*- coding: utf-8 -*-
#
from django.utils.translation import ugettext, ugettext_lazy as _

from rest_framework import serializers

from common.utils import get_signer, validate_ssh_public_key
from common.mixins import BulkSerializerMixin
from common.serializers import AdaptedBulkListSerializer
from ..utils import is_need_unblock
from ..models import User, UserGroup

signer = get_signer()


class UserSerializer(BulkSerializerMixin, serializers.ModelSerializer):
    groups_display = serializers.SerializerMethodField()
    role_display = serializers.SerializerMethodField()
    groups = serializers.PrimaryKeyRelatedField(many=True, queryset=UserGroup.objects.all(), required=False)
    finger_name = serializers.SerializerMethodField()
    fingerprint = serializers.SerializerMethodField()
    unblock = serializers.SerializerMethodField()

    class Meta:
        model = User
        list_serializer_class = AdaptedBulkListSerializer
        exclude = ['password','_otp_secret_key','_private_key','_public_key']
        extra_kwargs = {
            'groups_display': {'label': _('Groups name')},
            'source_display': {'label': _('Source name')},
            'is_first_login': {'label': _('Is first login'), 'read_only': True},
            'role_display': {'label': _('Role name')},
            'is_valid': {'label': _('Is valid')},
            'is_expired': {'label': _('Is expired')},
            'avatar_url': {'label': _('Avatar url')},
            'created_by': {'read_only': True}, 'source': {'read_only': True}
        }

    def get_field_names(self, declared_fields, info):
        fields = super().get_field_names(declared_fields, info)
        fields.extend(['groups_display', 'is_valid', 'role_display', 'get_source_display'])

        return fields

    @staticmethod
    def get_groups_display(obj):
        return ", ".join([group.name for group in obj.groups.all()])

    @staticmethod
    def get_role_display(obj):
        return _(obj.role.name)

    @staticmethod
    def get_finger_name(obj):
        return obj.public_key_obj.comment

    @staticmethod
    def get_fingerprint(obj):

        fingerprint = obj.public_key_obj.hash_md5
        if fingerprint:
            return obj.public_key_obj.hash_md5()
        else:
            return ''

    @staticmethod
    def get_unblock(obj):
        key_prefix_block = "_LOGIN_BLOCK_{}"
        key_block = key_prefix_block.format(obj.username)
        unblock = is_need_unblock(key_block)
        return unblock


class UserPKUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', '_public_key']

    @staticmethod
    def validate__public_key(value):
        if not validate_ssh_public_key(value):
            raise serializers.ValidationError(_('Not a valid ssh public key'))
        return value


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['phone', 'wechat', 'otp_level', 'username', 'name', 'email']


class UserUpdateGroupSerializer(serializers.ModelSerializer):
    groups = serializers.PrimaryKeyRelatedField(many=True, queryset=UserGroup.objects.all())

    class Meta:
        model = User
        fields = ['id', 'groups']


class UserGroupSerializer(BulkSerializerMixin, serializers.ModelSerializer):
    users = serializers.PrimaryKeyRelatedField(
        required=False, many=True, queryset=User.objects.all(), label=_('User')
    )
    managers_display = serializers.SerializerMethodField()
    managers_id = serializers.SerializerMethodField()

    class Meta:
        model = UserGroup
        list_serializer_class = AdaptedBulkListSerializer
        fields = '__all__'
        extra_kwargs = {
            'created_by': {'label': _('Created by'), 'read_only': True}
        }

    @staticmethod
    def get_managers_display(obj):
        return " ".join([manager.username for manager in obj.managers.all()])

    @staticmethod
    def get_managers_id(obj):
        managers_id = []
        for manager in obj.managers.all():
            managers_id.append(str(manager.id))
        return managers_id


class UserGroupUpdateMemberSerializer(serializers.ModelSerializer):
    users = serializers.PrimaryKeyRelatedField(many=True, queryset=User.objects.all())

    class Meta:
        model = UserGroup
        fields = ['id', 'users']


class ChangeUserPasswordSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ['password']
