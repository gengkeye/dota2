# -*- coding: utf-8 -*-
#
from __future__ import unicode_literals

from django.db import models
from django.utils.translation import gettext as _
from django.utils.translation import gettext_lazy

# Create your models here.
class Hero(models.Model):
    CATEGORY_CHOICES = (
        ("Strength", gettext_lazy("Strength")),
        ("Intelligence", gettext_lazy("Intelligence")),
        ("Agile", gettext_lazy("Agile")),
    )
    name = models.CharField(max_length=200, verbose_name=_("Name"))
    category = models.CharField(max_length=200, choices=CATEGORY_CHOICES, verbose_name=_("Hero Type"))
    dads = models.ManyToManyField('self', symmetrical=False, through='Relationship', through_fields=('son','dad'), related_name="sons", verbose_name=_("Dad Heros"))

    def __str__(self):
        return self.name

    def __unicode__(self):
        return self.__str__()

class Relationship(models.Model):
    STAR_CHOICES = (
        ('1', '1'),
        ('2', '2'),
        ('3', '3'),
        ('4', '4'),
        ('5', '5'),
    )
    dad = models.ForeignKey(Hero, on_delete=models.CASCADE, related_name='son', verbose_name=_("Dad Heros"))
    son = models.ForeignKey(Hero, on_delete=models.CASCADE, related_name='dad', verbose_name=_("Son Heros"))
    star = models.CharField(choices=STAR_CHOICES, max_length=10, verbose_name=_("Restrain Level"))
    reason = models.TextField(blank=True, verbose_name=_('Reason'))

    class Meta:
        unique_together = ('dad', 'son')
 
    def __str__(self):
        return "%s-%s" % (self.dad.name, self.son.name)

    def __unicode__(self):
        return self.__str__()