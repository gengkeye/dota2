from django.dispatch import Signal

post_user_create = Signal(providing_args=('user',))

from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from users.models import UserGroup, User, UserRole
from django.utils.translation import ugettext as _


# You should comment this signal when run: python manage loaddata init.
@receiver(pre_save, sender = User)
def update_user(sender, instance, raw, **kwargs):
    old_instance = User.objects.filter(id=instance.id)
    if old_instance and old_instance.first().role != instance.role:
        instance.navbars.clear()
        instance.dashboards.clear()
        role = instance.role
        if role is not None:
            for navbar in role.navbars.all():
                instance.navbars.add(navbar)
            for dashboard in role.dashboards.all():
                instance.dashboards.add(dashboard)

@receiver(post_save, sender = User)
def create_user(sender, instance, created, **kwargs):
    if created:
        if instance.role is None:
            instance.role = UserRole.objects.get(name='APP')
            instance.save()
        else:  
            role = instance.role
            for navbar in role.navbars.all():
                instance.navbars.add(navbar)
            for dashboard in role.dashboards.all():
                instance.dashboards.add(dashboard)

