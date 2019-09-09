# ~*~ coding: utf-8 ~*~
from __future__ import unicode_literals
from django.utils.translation import ugettext as _
from django.urls import reverse_lazy
from django.views.generic.base import TemplateView
from django.views.generic.edit import CreateView, UpdateView
from django.views.generic.detail import DetailView
from django.contrib.messages.views import SuccessMessageMixin

from common.utils import get_logger
from common.permissions import AdminUserRequiredMixin, AdminOrGroupAdminRequiredMixin, NavbarManagementMixin

from common.const import create_success_msg, update_success_msg
from orgs.utils import current_org
from ..models import User, UserGroup
from .. import forms

__all__ = ['UserGroupListView', 'UserGroupCreateView', 'UserGroupDetailView',
           'UserGroupUpdateView', 'UserGroupGrantedAssetView']
logger = get_logger(__name__)


class UserGroupListView(NavbarManagementMixin, TemplateView):
    template_name = 'users/user_group_list.html'

    def get_context_data(self, **kwargs):
        context = {
            'app': _('Users'),
            'action': _('User group list')
        }
        kwargs.update(context)
        return super().get_context_data(**kwargs)


class UserGroupCreateView(AdminUserRequiredMixin, SuccessMessageMixin, CreateView):
    model = UserGroup
    form_class = forms.UserGroupForm
    template_name = 'users/user_group_create_update.html'
    success_url = reverse_lazy('users:user-group-list')
    success_message = '<a href={url}> {name} </a> was created successfully'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        users = User.objects.all()
        context.update({'app': _('Users'), 'action': _('Create user group'),
                        'users': users})
        return context

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs.update({'user': self.request.user})
        return kwargs

    def form_valid(self, form):
        user_group = form.save()

        users_id_list = self.request.POST.getlist('users', [])
        managers_id_list = self.request.POST.getlist('managers', [])

        users = User.objects.filter(id__in=users_id_list)
        managers = User.objects.filter(id__in=managers_id_list)

        user_group.users.add(*users)
        user_group.managers.add(*managers)

        user_group.created_by = self.request.user.username or 'Admin'
        user_group.save()

        return super().form_valid(form)

    def get_success_message(self, cleaned_data):
        url = reverse_lazy('users:user-group-detail',
                           kwargs={'pk': self.object.id}
                           )
        return self.success_message.format(
            url=url, name=self.object.name
        )


class UserGroupUpdateView(AdminUserRequiredMixin, UpdateView):
    model = UserGroup
    form_class = forms.UserGroupForm
    template_name = 'users/user_group_create_update.html'
    success_url = reverse_lazy('users:user-group-list')

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs.update({'user': self.request.user})
        return kwargs

    def form_valid(self, form):
        obj = self.object
        users_id_list = self.request.POST.getlist('users', [])
        obj.users.set(User.objects.filter(id__in=users_id_list)) 

        if self.request.user.is_superadmin:
            managers_id_list = self.request.POST.getlist('managers', [])
            obj.managers.set(User.objects.filter(id__in=managers_id_list))

        obj.save()
        return super().form_valid(form)


    def get_context_data(self, **kwargs):
        context = {
            'app': _('Users'),
            'action': _('Update user group'),

        }
        kwargs.update(context)
        return super().get_context_data(**kwargs)


                
class UserGroupDetailView(AdminOrGroupAdminRequiredMixin, DetailView):
    model = UserGroup
    context_object_name = 'user_group'
    template_name = 'users/user_group_detail.html'

    def get_context_data(self, **kwargs):
        # users = User.objects.exclude(id__in=self.object.users.all())
        users = current_org.get_org_users().exclude(id__in=self.object.users.all())

        context = {
            'app': _('Users'),
            'action': _('User group detail'),
            'users': users,
        }
        kwargs.update(context)
        return super().get_context_data(**kwargs)


class UserGroupGrantedAssetView(AdminUserRequiredMixin, DetailView):
    model = UserGroup
    template_name = 'users/user_group_granted_asset.html'
    context_object_name = 'user_group'
    object = None

    def get_context_data(self, **kwargs):
        context = {
            'app': _('Users'),
            'action': _('User group granted asset'),
        }
        kwargs.update(context)
        return super().get_context_data(**kwargs)
