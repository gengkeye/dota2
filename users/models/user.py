#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
import uuid
import base64
import string
import random
from collections import OrderedDict

from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import AbstractUser
from django.core.cache import cache
from django.db import models
from django.utils.translation import ugettext_lazy as _
from django.utils import timezone
from django.shortcuts import reverse

from django.db.models import Q
import uuid
import datetime
from . import UserRole
from common.utils import get_signer, date_expired_default, get_logger

__all__ = ['User']

signer = get_signer()

logger = get_logger(__file__)


class User(AbstractUser):
    OTP_LEVEL_CHOICES = (
        (0, _('Disable')),
        (1, _('Enable')),
        (2, _("Force enable")),
    )
    SOURCE_LOCAL = 'local'
    SOURCE_LDAP = 'ldap'
    SOURCE_OPENID = 'openid'
    SOURCE_RADIUS = 'radius'
    SOURCE_CHOICES = (
        (SOURCE_LOCAL, 'Local'),
        (SOURCE_LDAP, 'LDAP/AD'),
        (SOURCE_OPENID, 'OpenID'),
        (SOURCE_RADIUS, 'Radius'),
    )

    CACHE_KEY_USER_RESET_PASSWORD_PREFIX = "_KEY_USER_RESET_PASSWORD_{}"

    id = models.UUIDField(default=uuid.uuid4, primary_key=True)
    username = models.CharField(
        max_length=128, unique=True, verbose_name=_('Username')
    )
    name = models.CharField(max_length=128, verbose_name=_('Name'))
    email = models.EmailField(
        max_length=128, unique=True, verbose_name=_('Email')
    )
    groups = models.ManyToManyField(
        'users.UserGroup', related_name='users',
        blank=True, verbose_name=_('User group')
    )
    avatar = models.ImageField(
        upload_to="avatar", null=True, verbose_name=_('Avatar')
    )
    wechat = models.CharField(
        max_length=128, blank=True, verbose_name=_('Wechat')
    )
    phone = models.CharField(
        max_length=20, blank=True, null=True, verbose_name=_('Phone')
    )
    otp_level = models.SmallIntegerField(
        default=0, choices=OTP_LEVEL_CHOICES, verbose_name=_('MFA')
    )
    _otp_secret_key = models.CharField(max_length=128, blank=True, null=True)
    # Todo: Auto generate key, let user download
    _private_key = models.CharField(
        max_length=5000, blank=True, verbose_name=_('Private key')
    )
    _public_key = models.CharField(
        max_length=5000, blank=True, verbose_name=_('Public key')
    )
    comment = models.TextField(
        max_length=200, blank=True, verbose_name=_('Comment')
    )
    is_first_login = models.BooleanField(default=True)
    date_expired = models.DateTimeField(
        default=date_expired_default, blank=True, null=True,
        db_index=True, verbose_name=_('Date expired')
    )
    created_by = models.CharField(
        max_length=30, default='', verbose_name=_('Created by')
    )
    managed_groups = models.ManyToManyField(
        'users.UserGroup', related_name='managers',
        blank=True, verbose_name=_('Managed Group')
    )
    role = models.ForeignKey(
        'users.UserRole', on_delete=models.SET_NULL, null=True, verbose_name=_('Role')
    )
    telegram_chat_id = models.CharField(
        max_length=30, unique=True, blank=True, null=True
    )
    telegram_username = models.CharField(
        max_length=30, unique=True, blank=True, null=True, verbose_name=_('TelegramUsername')
    )
    enable_telegram_notification = models.BooleanField(
        default=False, verbose_name=_('Enable Telegram Notifcation')
    )
    source = models.CharField(
        max_length=30, default=SOURCE_LOCAL, choices=SOURCE_CHOICES, verbose_name=_('Source'),
    )
    date_password_last_updated = models.DateTimeField(
        auto_now_add=True, blank=True, null=True,
        verbose_name=_('Date password last updated')
    )
    cmd_filters = models.ManyToManyField('assets.CommandFilter', related_name='users', verbose_name=_("Command filter"), blank=True)


    user_cache_key_prefix = '_User_{}'

    def __str__(self):
        return '{0.name}({0.username})'.format(self)

    @property
    def cmd_filter_rules(self):
        from assets.models import CommandFilterRule
        rules = CommandFilterRule.objects.filter(
            filter__in=self.cmd_filters.all()
        ).distinct()
        return rules

    @property
    def password_raw(self):
        raise AttributeError('Password raw is not a readable attribute')

    #: Use this attr to set user object password, example
    #: user = User(username='example', password_raw='password', ...)
    #: It's equal:
    #: user = User(username='example', ...)
    #: user.set_password('password')
    @password_raw.setter
    def password_raw(self, password_raw_):
        self.set_password(password_raw_)

    def set_password(self, raw_password):
        self._set_password = True
        if self.can_update_password():
            return super().set_password(raw_password)
        else:
            error = _("User auth from {}, go there change password").format(self.source)
            raise PermissionError(error)

    def can_update_password(self):
        return self.is_local

    @property
    def otp_secret_key(self):
        return signer.unsign(self._otp_secret_key)

    @otp_secret_key.setter
    def otp_secret_key(self, item):
        self._otp_secret_key = signer.sign(item)

    def check_otp(self, code):
        from ..utils import check_otp_code
        return check_otp_code(self.otp_secret_key, code)

    def get_absolute_url(self):
        return reverse('users:user-detail', args=(self.id,))

    def is_public_key_valid(self):
        """
            Check if the user's ssh public key is valid.
            This function is used in base.html.
        """
        if self._public_key:
            return True
        return False

    @property
    def groups_display(self):
        return ' '.join(self.groups.all().values_list('name', flat=True))

    @property
    def role_display(self):
        return self.get_role_display()

    @property
    def source_display(self):
        return self.get_source_display()

    @property
    def is_expired(self):
        return False
        #if self.date_expired and self.date_expired < datetime.datetime.now():
        #if self.date_expired:
        #    return True
        #else:
        #    return False

    @property
    def is_valid(self):
        if self.is_active and not self.is_expired:
            return True
        return False

    @property
    def private_key(self):
        return signer.unsign(self._private_key)

    @private_key.setter
    def private_key(self, private_key_raw):
        self._private_key = signer.sign(private_key_raw)

    @property
    def public_key(self):
        return signer.unsign(self._public_key)

    @public_key.setter
    def public_key(self, public_key_raw):
        self._public_key = signer.sign(public_key_raw)

    @property
    def public_key_obj(self):
        class PubKey(object):
            def __getattr__(self, item):
                return ''
        if self.public_key:
            import sshpubkeys
            try:
                return sshpubkeys.SSHKey(self.public_key)
            except (TabError, TypeError):
                pass
        return PubKey()

    @property
    def is_superuser(self):
        return self.role.name == 'Admin'

    @property
    def is_superadmin(self):
        return self.role.name in ['Admin', 'SecondaryAdmin']

    @is_superuser.setter
    def is_superuser(self, value):
        if value is True:
            self.role = UserRole.objects.get(name='Admin')
        else:
            self.role = UserRole.objects.get(name='User')

    @property
    def is_applier(self):
        return self.role.name in ['GroupAdmin', 'User']

    @property
    def is_admin(self):
        return self.role.name in ['GroupAdmin', 'Admin', 'SecondaryAdmin']

    @property
    def is_groupadmin(self):
        return self.role.name == 'GroupAdmin'

    @property
    def is_commonuser(self):
        return self.role.name == 'User'

    @property
    def admin_orgs(self):
        from orgs.models import Organization
        return Organization.get_user_admin_orgs(self)

    @property
    def is_org_admin(self):
        if self.is_superuser or self.admin_orgs.exists():
            return True
        else:
            return False

    @property
    def is_app(self):
        return self.role.name == 'App'

    @property
    def is_staff(self):
        if self.is_authenticated and self.is_valid:
            return True
        else:
            return False

    @is_staff.setter
    def is_staff(self, value):
        pass

    @property
    def is_local(self):
        return self.source == self.SOURCE_LOCAL
    
    @property
    def date_password_expired(self):
        interval = settings.SECURITY_PASSWORD_EXPIRATION_TIME
        if self.date_password_last_updated:
            date_expired = self.date_password_last_updated + timezone.timedelta(days=int(interval))
        else:
            date_expired = timezone.now() + timezone.timedelta(days=int(interval))
        return date_expired

    @property
    def password_expired_remain_days(self):
        date_remain = self.date_password_expired - timezone.now()
        return date_remain.days

    @property
    def password_has_expired(self):
        if self.is_local and self.password_expired_remain_days < 0:
            return True
        return False

    @property
    def password_will_expired(self):
        if self.is_local and self.password_expired_remain_days < 5:
            return True
        return False

    def save(self, *args, **kwargs):
        if not self.name:
            self.name = self.username
        if self.username == 'admin':
            self.role = UserRole.objects.get(name='Admin')
            self.is_active = True
        super().save(*args, **kwargs)
        self.expire_user_cache()

    @property
    def private_token(self):
        return self.create_private_token

    @property
    def managed_users(self):
        if self.is_superadmin:
            return User.objects.exclude(role__name__in=['App', 'SecondaryAdmin', 'Admin'])
        elif self.is_groupadmin:
            group_list = self.managed_groups.values_list('id',flat=True)
            return User.objects.filter(groups__id__in=list(group_list))
        else:
            return User.objects.filter(id__in=[self.id])

    @property
    def assets(self):
        from assets.models import Asset
        if self.is_superadmin:
            return Asset.objects.all()
        elif self.is_groupadmin:
            return self.granted_assets_direct | \
                self.granted_assets_inherit_from_user_groups | \
                self.granted_assets_inherit_from_nodes
        else:
            return self.granted_assets_direct

    @property
    def windowsassets(self):
        from assets.models import WindowsAsset
        if self.is_superadmin:
            return WindowsAsset.objects.all()
        elif self.is_groupadmin:
            return self.granted_assets_direct | \
                self.granted_assets_inherit_from_user_groups
        else:
            return self.granted_assets_direct

    @property
    def ports(self):
        from ...applications.models.applications import Port
        if self.is_superadmin:
            return Port.objects.all()
        elif self.is_groupadmin:
            return self.granted_assets_direct | \
                self.granted_assets_inherit_from_user_groups
        else:
            return self.granted_assets_direct

    @property
    def asset_groups(self):
        if self.is_superadmin:
            from assets.models import AssetGroup
            return AssetGroup.objects.all()
        else:
            return self.created_asset_groups.all() | \
                self.granted_asset_groups_direct | \
                self.granted_asset_groups_inherit_from_user_groups

    @property
    def can_apply_asset_groups(self):
        from assets.models import AssetGroup
        asset_groups = AssetGroup.objects.none()
        if self.is_groupadmin:
            asset_groups |= AssetGroup.objects.filter(creater__role__name='Admin')
        elif self.is_commonuser:
            manager_list = self.group_managers.values_list('id', flat=True)
            asset_groups |= AssetGroup.objects.filter(creater__id__in=list(manager_list))
        return asset_groups

    @property
    def nodes(self):
        if self.is_superadmin:
            from assets.models import Node
            nodes = Node.objects.order_by('key')
        else:
            nodes = self.granted_nodes_direct | \
                self.granted_nodes_inherit_from_user_groups
        return nodes.order_by('key')
        
    @property
    def system_users(self):
        from assets.models import SystemUser
        if self.is_superadmin:
            return SystemUser.objects.all()
        else:
            from perms.utils import AssetPermissionUtil
            system_users = SystemUser.objects.none()
            for v in AssetPermissionUtil(self).get_assets().values():
                for system_user in v:
                    system_users |= SystemUser.objects.filter(pk=system_user.pk)
            return system_users.exclude(username__in=['superadministrator', 'administrator'])

    @property
    def can_apply_nodes(self):
        from assets.models import Node
        nodes = Node.objects.none()
        if self.is_groupadmin:
            nodes |= Node.objects.all()
        # elif self.is_commonuser:
        #     for manager in self.group_managers.all():
        #         for node in manager.nodes:
        #             nodes |= node.get_all_children()
        #     nodes.exclude(value='Root')
        return nodes.order_by('key')

    @property
    def can_apply_assets(self):
        from assets.models import Asset
        valid_assets = Asset.valid_assets()
        assets = Asset.objects.none()
        if self.is_groupadmin:
            assets |= valid_assets
        elif self.is_commonuser:
            for manager in self.group_managers:
                assets |= manager.assets
        return assets

    @property
    def can_apply_system_users(self):
        from assets.models import SystemUser
        system_users = SystemUser.objects.none()
        if self.is_groupadmin:
            system_users = SystemUser.objects.all()
        elif self.is_commonuser:
            for manager in self.group_managers:
                system_users |= manager.system_users
            system_users.exclude(username__in=['superadministrator', 'administrator'])
        return system_users

    @property
    def group_managers(self):
        if self.is_commonuser:
            managers = User.objects.none()
            for g in self.groups.all():
                managers |= g.managers.all()
            return managers.distinct()
        return User.objects.filter(role__name='Admin')

    @property
    def granted_assets_direct(self):
        from assets.models import Asset
        valid_assets = Asset.valid_assets()
        asset_perms_list = self.assetpermission_set.filter(
            is_active=True,
            date_expired__gt=timezone.now(),
        ).values_list('id', flat=True)
        nodes_list = self.granted_nodes_direct.values_list('id', flat=True)
        return valid_assets.filter(
            Q(granted_by_permissions__id__in=list(asset_perms_list)) |
            Q(nodes__id__in=list(nodes_list))
        ).distinct()

    @property
    def granted_assets_inherit_from_user_groups(self):
        from assets.models import Asset
        from perms.models import AssetPermission
        valid_assets = Asset.valid_assets()
        group_list = self.groups.values_list('id', flat=True)
        asset_perms_list = AssetPermission.objects.all().valid().filter(
            user_groups__id__in=list(group_list)
        ).values_list('id', flat=True)
        nodes_list = self.granted_nodes_inherit_from_user_groups \
            .values_list('id', flat=True)
        return valid_assets.filter(
            Q(granted_by_permissions__id__in=list(asset_perms_list)) |
            Q(nodes__id__in=list(nodes_list))
        ).distinct()

    @property
    def granted_assets_inherit_from_nodes(self):
        from assets.models import Asset
        assets = Asset.objects.none()
        for node in self.nodes:
            assets |= node.get_valid_assets()
        return assets.distinct()

    @property
    def granted_asset_groups_direct(self):
        from assets.models import AssetGroup
        asset_perms_list = self.assetpermission_set.values_list('id', flat=True)
        return AssetGroup.objects.filter(granted_by_permissions__id__in=list(asset_perms_list))

    @property
    def granted_asset_groups_inherit_from_user_groups(self):
        from assets.models import AssetGroup
        from perms.models import AssetPermission
        group_list= self.groups.values_list('id', flat=True)
        asset_perms_list = AssetPermission.objects.all().valid().filter(
            user_groups__id__in=list(group_list)
        ).values_list('id', flat=True)
        return AssetGroup.objects.filter(granted_by_permissions__id__in=list(asset_perms_list))

    @property
    def granted_nodes_direct(self):
        from assets.models import Node
        asset_perms_list = self.assetpermission_set.values_list('id', flat=True)
        nodes = Node.objects.none()
        for node in Node.objects.filter(granted_by_permissions__id__in=list(asset_perms_list)):
            nodes |= node.get_all_children()
        return nodes

    @property
    def granted_nodes_inherit_from_user_groups(self):
        from assets.models import Node
        from perms.models import AssetPermission
        nodes = Node.objects.none()
        group_list= self.groups.values_list('id', flat=True)
        asset_perms_list = AssetPermission.objects.all().valid().filter(
            user_groups__id__in=list(group_list)
        ).values_list('id', flat=True)
        for node in Node.objects.filter(granted_by_permissions__id__in=list(asset_perms_list)):
            nodes |= node.get_all_children()
        return nodes

    @property
    def create_private_token(self):
        from authentication.models import PrivateToken
        try:
            token = PrivateToken.objects.get(user=self)
        except PrivateToken.DoesNotExist:
            token = self.create_private_token()
        return token

    def create_private_token(self):
        from authentication.models import PrivateToken
        token = PrivateToken.objects.create(user=self)
        return token

    def refresh_private_token(self):
        self.private_token.delete()
        return self.create_private_token()

    def create_bearer_token(self, request=None):
        expiration = settings.TOKEN_EXPIRATION or 3600
        if request:
            remote_addr = request.META.get('REMOTE_ADDR', '')
        else:
            remote_addr = '0.0.0.0'
        if not isinstance(remote_addr, bytes):
            remote_addr = remote_addr.encode("utf-8")
        remote_addr = base64.b16encode(remote_addr)  # .replace(b'=', '')
        cache_key = '%s_%s' % (self.id, remote_addr)
        token = cache.get(cache_key)
        if not token:
            token = uuid.uuid4().hex
        cache.set(token, self.id, expiration)
        cache.set('%s_%s' % (self.id, remote_addr), token, expiration)
        return token

    def refresh_bearer_token(self, token):
        pass

    def create_access_key(self):
        access_key = self.access_keys.create()
        return access_key

    @property
    def access_key(self):
        return self.access_keys.first()

    def is_member_of(self, user_group):
        if user_group in self.groups.all():
            return True
        return False

    def avatar_url(self):
        admin_default = settings.STATIC_URL + "img/avatar/admin.png"
        user_default = settings.STATIC_URL + "img/avatar/user.png"
        if self.avatar:
            return self.avatar.url
        if self.is_superadmin:
            return admin_default
        else:
            return user_default

    def generate_reset_token(self):
        letter = string.ascii_letters + string.digits
        token =''.join([random.choice(letter) for _ in range(50)])
        self.set_cache(token)
        return token

    def set_cache(self, token):
        key = self.CACHE_KEY_USER_RESET_PASSWORD_PREFIX.format(token)
        cache.set(key, {'id': self.id, 'email': self.email}, 3600)

    @classmethod
    def validate_reset_password_token(cls, token):
        try:
            key = cls.CACHE_KEY_USER_RESET_PASSWORD_PREFIX.format(token)
            value = cache.get(key)
            user_id = value.get('id', '')
            email = value.get('email', '')
            user = cls.objects.get(id=user_id, email=email)
        except (AttributeError, cls.DoesNotExist) as e:
            logger.error(e, exc_info=True)
            user = None
        return user

    @classmethod
    def expired_reset_password_token(cls, token):
        key = cls.CACHE_KEY_USER_RESET_PASSWORD_PREFIX.format(token)
        cache.delete(key)

    @property
    def otp_enabled(self):
        return self.otp_force_enabled or self.otp_level > 0

    @property
    def otp_force_enabled(self):
        if settings.SECURITY_MFA_AUTH:
            return True
        return self.otp_level == 2

    def enable_otp(self):
        if not self.otp_level == 2:
            self.otp_level = 1

    def force_enable_otp(self):
        self.otp_level = 2

    def disable_otp(self):
        self.otp_level = 0
        self.otp_secret_key = None

    def to_json(self):
        return OrderedDict({
            'id': self.id,
            'username': self.username,
            'name': self.name,
            'email': self.email,
            'is_active': self.is_active,
            'is_superuser': self.is_superadmin,
            'role': self.role.name,
            'groups': [group.name for group in self.groups.all()],
            'source': self.get_source_display(),
            'wechat': self.wechat,
            'phone': self.phone,
            'otp_level': self.otp_level,
            'comment': self.comment,
            'date_expired': self.date_expired.strftime('%Y-%m-%d %H:%M:%S') \
                if self.date_expired is not None else None
        })

    @classmethod
    def create_app_user(cls, name, comment):
        app = cls.objects.create(
            username=name, name=name, email='{}@local.domain'.format(name),
            is_active=False, role=UserRole.objects.get(name='App'), comment=comment,
            is_first_login=False, created_by='System'
        )
        access_key = app.create_access_key()
        return app, access_key

    def reset_password(self, new_password):
        self.set_password(new_password)
        self.date_password_last_updated = timezone.now()
        self.save()

    def delete(self, using=None, keep_parents=False):
        if self.pk == 1 or self.username == 'admin':
            return
        self.expire_user_cache()
        return super(User, self).delete()

    def expire_user_cache(self):
        key = self.user_cache_key_prefix.format(self.id)
        cache.delete(key)

    @classmethod
    def get_user_or_from_cache(cls, uid):
        key = cls.user_cache_key_prefix.format(uid)
        user = cache.get(key)
        if user:
            return user
        try:
            user = cls.objects.get(id=uid)
            cache.set(key, user, 3600)
        except cls.DoesNotExist:
            user = None
        return user

    class Meta:
        ordering = ['username']
        verbose_name = _("User")

    #: Use this method initial user
    @classmethod
    def initial(cls):
        from .group import UserGroup
        user = cls(username='admin',
                   email='admin@TechDog',
                   name=_('Administrator'),
                   password_raw='admin',
                   role=UserRole.objects.get(name='Admin'),
                   comment=_('Administrator is the super user of system'),
                   created_by=_('System'))
        user.save()
        user.groups.add(UserGroup.initial())

    @classmethod
    def generate_fake(cls, count=100):
        from random import seed, choice
        import forgery_py
        from django.db import IntegrityError
        from .group import UserGroup

        seed()
        roles = UserRole.objects.all()
        for i in range(count):
            user = cls(username=forgery_py.internet.user_name(True),
                       email=forgery_py.internet.email_address(),
                       name=forgery_py.name.full_name(),
                       password=make_password(forgery_py.lorem_ipsum.word()),
                       role=choice(roles),
                       wechat=forgery_py.internet.user_name(True),
                       comment=forgery_py.lorem_ipsum.sentence(),
                       created_by=choice(cls.objects.all()).username)
            try:
                user.save()
            except IntegrityError:
                print('Duplicate Error, continue ...')
                continue
            user.groups.add(choice(UserGroup.objects.all()))
            user.save()
