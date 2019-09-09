#!/usr/bin/env python
# -*- coding: utf-8 -*-
#

from __future__ import unicode_literals
from django.db import models
from django.utils.translation import ugettext_lazy as _


class UserRole(models.Model):
	ROLE_CHOICES = (
	    ('Admin', _('Admin')),
	    ('SecondaryAdmin', _('SecondaryAdmin')),
	    ('GroupAdmin', _('GroupAdmin')),
	    ('User', _('User')),
	    ('App', _('App'))
	)
	name = models.CharField(choices=ROLE_CHOICES, max_length=20, unique=True, verbose_name=_('Name'))

	def __unicode__(self):
	    return self.name
	__str__ = __unicode__