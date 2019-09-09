# ~*~ coding: utf-8 ~*~

from django import forms
from django.utils.translation import gettext_lazy as _

from common.utils import validate_ssh_public_key
from .models import User, UserRole, UserGroup
from navbars.models import Navbar
from dashboards.models import Dashboard
from orgs.mixins import OrgModelForm
from orgs.utils import current_org
from .models import User, UserGroup


class UserCheckPasswordForm(forms.Form):
    username = forms.CharField(label=_('Username'), max_length=100)
    password = forms.CharField(
        label=_('Password'), widget=forms.PasswordInput,
        max_length=128, strip=False
    )


class UserCheckOtpCodeForm(forms.Form):
    otp_code = forms.CharField(label=_('MFA code'), max_length=6)


class UserCreateUpdateFormMixin(OrgModelForm):
    password = forms.CharField(
        label=_('Password'), widget=forms.PasswordInput,
        max_length=128, strip=False, required=False,
    )
    public_key = forms.CharField(
        label=_('ssh public key'), max_length=5000, required=False,
        widget=forms.Textarea(attrs={'placeholder': _('ssh-rsa AAAA...')}),
        help_text= _("Paste user id_rsa.pub here.")
    )

    navbars = forms.ModelMultipleChoiceField(
        queryset=Navbar.objects.none(),
        label=_('Navbars'),
        required=False,
        widget=forms.CheckboxSelectMultiple(
            attrs = {'class': 'row'}
        ),
    )

    dashboards = forms.ModelMultipleChoiceField(
        queryset=Dashboard.objects.all(),
        label=_('Dashboard'),
        required=False,
        widget = forms.CheckboxSelectMultiple()
    )

    user_role = forms.ChoiceField(
        choices=UserRole.ROLE_CHOICES,
        required=True,
        label=_("Role"),
        widget=forms.Select(
            attrs={
                'class': 'select2',
            }
        )
    )

    def __init__(self, *args, **kwargs):
        instance = kwargs.get('instance', None)
        self.user = kwargs.pop('user', None)
        self.target_user = kwargs.pop('target_user', None)
        super().__init__(*args, **kwargs)
        if not self.user.is_superuser:
            self.fields['user_role'].choices = (
                ('GroupAdmin', _('GroupAdmin')),
                ('User', _('User')),
            )

        self.fields['navbars'].queryset = Navbar.objects.all().order_by('sort')
        if instance:
            self.fields['navbars'].initial = instance.navbars.all()
            self.fields['dashboards'].initial = instance.dashboards.all()
            self.initial['user_role'] = instance.role.name

    class Meta:
        model = User
        fields = [
            'username', 'name', 'email', 'groups', 'wechat',
            'phone', 'date_expired', 'comment',
            'navbars', 'dashboards', 'otp_level'
        ]
        widgets = {
            'otp_level': forms.RadioSelect(),
            'groups': forms.SelectMultiple(
                attrs={
                    'class': 'select2',
                    'data-placeholder': _('Join user groups')
                }
            )
        }

    def clean_public_key(self):
        public_key = self.cleaned_data['public_key']
        if not public_key:
            return public_key
        if self.instance.public_key and public_key == self.instance.public_key:
            msg = _('Public key should not be the same as your old one.')
            raise forms.ValidationError(msg)

        if not validate_ssh_public_key(public_key):
            raise forms.ValidationError(_('Not a valid ssh public key'))
        return public_key

    def save(self, commit=True):
        password = self.cleaned_data.get('password')
        otp_level = self.cleaned_data.get('otp_level')
        public_key = self.cleaned_data.get('public_key')
        user = super().save(commit=commit)
        if password:
            user.reset_password(password)
        if otp_level:
            user.otp_level = otp_level
            user.save()
        if public_key:
            user.public_key = public_key
            user.save()
        return user

    def clean_user_role(self):
        user_role = self.cleaned_data.get('user_role')
        if not self.user.is_superuser and user_role in ['Admin', 'SecondaryAdmin']:
            raise forms.ValidationError(_('Invalid values'))
        return self.cleaned_data['user_role']

class UserCreateForm(UserCreateUpdateFormMixin):
    EMAIL_SET_PASSWORD = _('Reset link will be generated and sent to the user')
    CUSTOM_PASSWORD = _('Set password')
    PASSWORD_STRATEGY_CHOICES = (
        (0, EMAIL_SET_PASSWORD),
        (1, CUSTOM_PASSWORD)
    )
    password_strategy = forms.ChoiceField(
        choices=PASSWORD_STRATEGY_CHOICES, required=True, initial=0,
        widget=forms.RadioSelect(), label=_('Password strategy')
    )


class UserUpdateForm(UserCreateUpdateFormMixin):
    pass


class UserProfileForm(forms.ModelForm):
    username = forms.CharField(disabled=True)
    name = forms.CharField(disabled=True)
    email = forms.CharField(disabled=True)

    class Meta:
        model = User
        fields = [
            'username', 'name', 'email',
            'wechat', 'phone',
        ]
        help_texts = {
            'username': '* required',
            'name': '* required',
        }


UserProfileForm.verbose_name = _("Profile")


class UserMFAForm(forms.ModelForm):

    mfa_description = _(
        'Tip: when enabled, '
        'you will enter the MFA binding process the next time you log in. '
        'you can also directly bind in '
        '"personal information -> quick modification -> change MFA Settings"!')

    class Meta:
        model = User
        fields = ['otp_level']
        widgets = {'otp_level': forms.RadioSelect()}
        help_texts = {
            'otp_level': _('* Enable MFA authentication '
                           'to make the account more secure.'),
        }


UserMFAForm.verbose_name = _("MFA")


class UserFirstLoginFinishForm(forms.Form):
    finish_description = _(
        'In order to protect you and your company, '
        'please keep your account, '
        'password and key sensitive information properly. '
        '(for example: setting complex password, enabling MFA authentication)'
    )


UserFirstLoginFinishForm.verbose_name = _("Finish")


class UserPasswordForm(forms.Form):
    old_password = forms.CharField(
        max_length=128, widget=forms.PasswordInput,
        label=_("Old password")
    )
    new_password = forms.CharField(
        min_length=5, max_length=128,
        widget=forms.PasswordInput,
        label=_("New password")
    )
    confirm_password = forms.CharField(
        min_length=5, max_length=128,
        widget=forms.PasswordInput,
        label=_("Confirm password")
    )

    def __init__(self, *args, **kwargs):
        self.instance = kwargs['data'].pop('instance')
        super().__init__(*args, **kwargs)

    def clean_old_password(self):
        old_password = self.cleaned_data['old_password']
        if not self.instance.check_password(old_password):
            raise forms.ValidationError(_('Old password error'))
        return old_password

    def clean_confirm_password(self):
        new_password = self.cleaned_data['new_password']
        confirm_password = self.cleaned_data['confirm_password']

        if new_password != confirm_password:
            raise forms.ValidationError(_('Password does not match'))
        return confirm_password

    def save(self):
        password = self.cleaned_data['new_password']
        self.instance.reset_password(new_password=password)
        return self.instance


class UserPublicKeyForm(forms.Form):
    pubkey_description = _('Automatically configure and download the SSH key')
    public_key = forms.CharField(
        label=_('ssh public key'), max_length=5000, required=False,
        widget=forms.Textarea(attrs={'placeholder': _('ssh-rsa AAAA...')}),
        help_text=_('Paste your id_rsa.pub here.')
    )

    def __init__(self, *args, **kwargs):
        if 'instance' in kwargs:
            self.instance = kwargs.pop('instance')
        else:
            self.instance = None
        super().__init__(*args, **kwargs)

    def clean_public_key(self):
        public_key = self.cleaned_data['public_key']
        if self.instance.public_key and public_key == self.instance.public_key:
            msg = _('Public key should not be the same as your old one.')
            raise forms.ValidationError(msg)

        if public_key and not validate_ssh_public_key(public_key):
            raise forms.ValidationError(_('Not a valid ssh public key'))
        return public_key

    def save(self):
        public_key = self.cleaned_data['public_key']
        if public_key:
            self.instance.public_key = public_key
            self.instance.save()
        return self.instance


UserPublicKeyForm.verbose_name = _("Public key")


class UserBulkUpdateForm(OrgModelForm):
    users = forms.ModelMultipleChoiceField(
        required=True,
        label=_('Select users'),
        queryset=User.objects.all(),
        widget=forms.SelectMultiple(
            attrs={
                'class': 'select2',
                'data-placeholder': _('Select users')
            }
        )
    )

    class Meta:
        model = User
        fields = ['users', 'groups', 'date_expired']
        widgets = {
            "groups": forms.SelectMultiple(
                attrs={
                    'class': 'select2',
                    'data-placeholder': _('User group')
                }
            )
        }

    def save(self, commit=True):
        changed_fields = []
        for field in self._meta.fields:
            if self.data.get(field) is not None:
                changed_fields.append(field)

        cleaned_data = {k: v for k, v in self.cleaned_data.items()
                        if k in changed_fields}
        users = cleaned_data.pop('users', '')
        groups = cleaned_data.pop('groups', [])
        users = User.objects.filter(id__in=[user.id for user in users])
        users.update(**cleaned_data)
        if groups:
            for user in users:
                user.groups.set(groups)
        return users


def user_limit_to():
    return {"orgs": current_org}


class UserGroupForm(OrgModelForm):
    users = forms.ModelMultipleChoiceField(
        queryset=User.objects.exclude(role__name='App'),
        label=_("User"),
        widget=forms.SelectMultiple(
            attrs={
                'class': 'select2',
                'data-placeholder': _('Select users')
            }
        ),
        required=False,
        limit_choices_to=user_limit_to
    )

    managers = forms.ModelMultipleChoiceField(
        queryset=User.objects.filter(role__name__in=['Admin', 'GroupAdmin']),
        label=_('GroupAdministrator'),
        required=False,
        widget=forms.SelectMultiple(
            attrs={'class': 'select2', 'data-placeholder': _('Select group managers')})
    )

    def __init__(self, *args, **kwargs):
        self.is_superadmin = kwargs.pop('user', None).is_superadmin
        instance = kwargs.get('instance', None)
        super().__init__(*args, **kwargs)
        self.fields['managers'].widget.attrs['disabled'] = not self.is_superadmin
        self.fields['name'].widget.attrs['readonly'] = not self.is_superadmin
        if instance:
            self.fields['users'].initial= instance.users.values_list('id', flat=True)
            self.fields['managers'].initial= instance.managers.values_list('id', flat=True)
            initial = kwargs.get('initial', {})
            initial.update({'users': instance.users.all()})
            kwargs['initial'] = initial
        super().__init__(**kwargs)
        if 'initial' not in kwargs:
            return
        users_field = self.fields.get('users')
        if hasattr(users_field, 'queryset'):
            users_field.queryset = current_org.get_org_users()


    class Meta:
        model = UserGroup
        fields = [
            'name', 'managers', 'users', 'comment'

        ]

    def clean_name(self):
        name = self.cleaned_data['name']
        if name.lower() in ['default', 'admin', 'administrator'] and not self.is_superadmin:
            raise forms.ValidationError(_("You can't use the name Default or Admin"))
        return name

    def save(self, commit=True):
        group = super().save(commit=commit)
        users = self.cleaned_data['users']
        group.users.set(users)
        return group


class FileForm(forms.Form):
    file = forms.FileField()
