# ~*~ coding: utf-8 ~*~
import uuid

from django.core.cache import cache
from django.contrib.auth import logout
from django.utils.translation import ugettext as _

from rest_framework import status
from rest_framework import generics
from rest_framework.views import APIView
from rest_framework.response import Response

from django.http import HttpResponse, JsonResponse, HttpResponseRedirect
from rest_framework.permissions import IsAuthenticated
from rest_framework_bulk import BulkModelViewSet
from rest_framework.pagination import LimitOffsetPagination
from django.shortcuts import redirect

from common.permissions import (
    IsOrgAdmin, IsCurrentUserOrReadOnly, IsOrgAdminOrAppUser, IsValidUser
)
from common.mixins import IDInCacheFilterMixin
from common.utils import get_logger
from orgs.utils import current_org
from users.serializers import UserSerializer, UserPKUpdateSerializer, \
    UserUpdateGroupSerializer, ChangeUserPasswordSerializer, UserProfileSerializer
from users.models import User, UserRole
from users.signals import post_user_create
from navbars.serializers import NavbarSerializer
from django.urls import reverse_lazy, reverse

from common.utils import ssh_key_gen
from users import forms
from users.forms import UserPasswordForm
from users.utils import check_password_rules

logger = get_logger(__name__)


class UserViewSet(IDInCacheFilterMixin, BulkModelViewSet):
    filter_fields = ('username', 'email', 'name', 'id', 'role__name')
    search_fields = filter_fields
    serializer_class = UserSerializer
    permission_classes = (IsOrgAdmin,)
    pagination_class = LimitOffsetPagination

    def send_created_signal(self, users):
        if not isinstance(users, list):
            users = [users]
        for user in users:
            post_user_create.send(self.__class__, user=user)

    def perform_create(self, serializer):
        serializer.validated_data['password_raw'] = self.request.data['password']
        users = serializer.save()
        self.send_created_signal(users)

    def get_queryset(self):
        queryset = current_org.get_org_users()
        return queryset

    def get_permissions(self):
        if self.action == "retrieve":
            self.permission_classes = (IsOrgAdminOrAppUser,)
        return super().get_permissions()

    def _deny_permission(self, instance):
        """
        check current user has permission to handle instance
        (update, destroy, bulk_update, bulk destroy)
        """
        return not self.request.user.is_superuser and instance.is_superuser

    def destroy(self, request, *args, **kwargs):
        """
        rewrite because limit org_admin destroy superuser
        """
        instance = self.get_object()
        if self._deny_permission(instance):
            data = {'msg': _("You do not have permission.")}
            return Response(data=data, status=status.HTTP_403_FORBIDDEN)

        return super().destroy(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        """
        rewrite because limit org_admin update superuser
        """
        instance = self.get_object()
        if self._deny_permission(instance):
            data = {'msg': _("You do not have permission.")}
            return Response(data=data, status=status.HTTP_403_FORBIDDEN)

        return super().update(request, *args, **kwargs)

    def perform_update(self, serializer):
        if self.request.data['password']:
            serializer.validated_data['password_raw'] = self.request.data['password']
        serializer.save()

    def _bulk_deny_permission(self, instances):
        deny_instances = [i for i in instances if self._deny_permission(i)]
        if len(deny_instances) > 0:
            return True
        else:
            return False

    def allow_bulk_destroy(self, qs, filtered):
        if self._bulk_deny_permission(filtered):
            return False
        return qs.count() != filtered.count()

    def bulk_update(self, request, *args, **kwargs):
        """
        rewrite because limit org_admin update superuser
        """
        partial = kwargs.pop('partial', False)

        # restrict the update to the filtered queryset
        queryset = self.filter_queryset(self.get_queryset())
        if self._bulk_deny_permission(queryset):
            data = {'msg': _("You do not have permission.")}
            return Response(data=data, status=status.HTTP_403_FORBIDDEN)

        serializer = self.get_serializer(
            queryset, data=request.data, many=True, partial=partial,
        )

        try:
            serializer.is_valid(raise_exception=True)
        except Exception as e:
            data = {'error': str(e)}
            return Response(data=data, status=status.HTTP_400_BAD_REQUEST)

        self.perform_bulk_update(serializer)
        return Response(serializer.data, status=status.HTTP_200_OK)


class UserFirstLoginFinishApi(APIView):
    permission_classes = (IsValidUser,)

    def get(self, request):
        user = self.request.user
        user.is_first_login=False
        user.is_public_key_valid=True
        user.save()

        return HttpResponseRedirect(reverse("users:user-profile"))


class UserChangePasswordApi(generics.RetrieveUpdateAPIView):
    permission_classes = (IsOrgAdmin,)
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        request_data = request.data
        request_data['instance'] = instance
        form = UserPasswordForm(data=request_data)

        if form.is_valid():
            instance.password_raw = form.cleaned_data['new_password']
            instance.save()
            return JsonResponse({"success": True, "message": "密码修改成功"}, status=200)
        else:
            return JsonResponse({"success": False, "message": form.errors})

    def form_valid(self, form):
        if not self.request.user.can_update_password():
            error = _("User auth from {}, go there change password").format(
                self.request.source_display
            )
            form.add_error("password", error)
            return self.form_invalid(form)
        password = form.cleaned_data.get('new_password')
        is_ok = check_password_rules(password)
        if not is_ok:
            form.add_error(
                "new_password",
                _("* Your password does not meet the requirements")
            )
            return self.form_invalid(form)
        return super().form_valid(form)


class UserUpdateGroupApi(generics.RetrieveUpdateAPIView):
    queryset = User.objects.all()
    serializer_class = UserUpdateGroupSerializer
    permission_classes = (IsOrgAdmin,)


class UserResetPasswordApi(generics.UpdateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = (IsAuthenticated,)

    def perform_update(self, serializer):
        # Note: we are not updating the user object here.
        # We just do the reset-password stuff.
        from ..utils import send_reset_password_mail
        user = self.get_object()
        user.password_raw = str(uuid.uuid4())
        user.save()
        send_reset_password_mail(user)


class UserResetPKApi(generics.RetrieveAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = (IsAuthenticated,)

    def retrieve(self, request, *args, **kwargs):
        private, public = ssh_key_gen(username=request.user.username, hostname='jumpserver')
        request.user.public_key = public
        request.user.save()
        response = HttpResponse(private, content_type='text/plain')
        filename = "{0}-jumpserver.pem".format(request.user.username)
        response['Content-Disposition'] = 'attachment; filename={}'.format(filename)
        return response


class UserUpdatePKApi(generics.UpdateAPIView):
    queryset = User.objects.all()
    serializer_class = UserPKUpdateSerializer
    permission_classes = (IsCurrentUserOrReadOnly,)

    def perform_update(self, serializer):
        user = self.get_object()
        user.public_key = serializer.validated_data['_public_key']
        user.save()


class UserUnblockPKApi(generics.UpdateAPIView):
    queryset = User.objects.all()
    permission_classes = (IsOrgAdmin,)
    serializer_class = UserSerializer
    key_prefix_limit = "_LOGIN_LIMIT_{}_{}"
    key_prefix_block = "_LOGIN_BLOCK_{}"

    def perform_update(self, serializer):
        user = self.get_object()
        username = user.username if user else ''
        key_limit = self.key_prefix_limit.format(username, '*')
        key_block = self.key_prefix_block.format(username)
        cache.delete_pattern(key_limit)
        cache.delete(key_block)


class UserProfileApi(generics.RetrieveUpdateAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = UserSerializer

    def get_object(self):
        return self.request.user


class UserResetOTPApi(generics.RetrieveAPIView):
    queryset = User.objects.all()
    permission_classes = (IsOrgAdmin,)
    serializer_class = UserSerializer

    def retrieve(self, request, *args, **kwargs):
        user = self.get_object() if kwargs.get('pk') else request.user
        if user == request.user:
            msg = _("Could not reset self otp, use profile reset instead")
            return Response({"error": msg}, status=401)
        if user.otp_enabled and user.otp_secret_key:
            user.otp_secret_key = ''
            user.save()
            logout(request)
        return Response({"msg": "success"})


class UserCommandFilterRuleListApi(generics.ListAPIView):
    permission_classes = (IsOrgAdminOrAppUser,)

    def get_serializer_class(self):
        from assets.serializers import CommandFilterRuleSerializer
        return CommandFilterRuleSerializer

    def get_queryset(self):
        pk = self.kwargs.get('pk', None)
        user = get_object_or_404(User, pk=pk)
        return user.cmd_filter_rules


class UserNamesViewset(APIView):
    permission_classes = (IsValidUser,)

    def get(self, request, *args, **kwargs):   
        names = list(User.objects.values('username', 'id'))
        return Response(names, status=200)


class UserRolesViewset(APIView):
    permission_classes = (IsValidUser,)

    def get(self, request, *args, **kwargs):   
        names = list(UserRole.objects.values('name', 'id'))
        return Response(names, status=200)


class UserNavbarsAPI(APIView):
    permission_classes = (IsValidUser,)
    serializer_class = NavbarSerializer
    def get(self, request, *args, **kwargs):
        user = self.request.user
        navbars = user.navbars.all()
        data = []
         # {
         #    name: "仪表盘", /边栏导航栏显示的文字/
         #    type: "dashboard", /图标/
         #    router: "dashboard", /面包屑导航/
         #  }
        for parent in navbars.filter(level=1).order_by('sort'):
            menu = {
               "name": _(parent.name),
               "type": parent.i_css,
               "router": parent.name,
               "submenu": [],
            }
            for child in parent.child_navbars.all().order_by('sort'):
                submenu = {
                   "name": _(child.name),
                   "type": child.i_css,
                   "router": child.name,
                }
                menu["submenu"].append(submenu)

            data.append(menu)
        return Response(data, status=200)


class UserSystemUserAPI(APIView):
    permission_classes = (IsValidUser,)

    def get(self, request, *args, **kwargs):
        try:
            user = self.request.user
            from perms.utils import AssetPermissionUtil
            user = self.request.user
            util = AssetPermissionUtil(user)
            system_users = [{"system_user_id" : str(s.id), "system_user_name": s.username} for s in util.get_system_users() if s.protocol == 'ssh']
            return JsonResponse({"success": True, "data": system_users}, status=200)

        except Exception:
            return JsonResponse({"success": False, "message": "get system user error"})
        
