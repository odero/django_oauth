from django.db import models
from django.contrib.auth.models import User

# Create your models here.

APP_TYPES = (
    (u'd', u'Desktop'),
    (u'b', u'Browser'),
)

PERMISSIONS = (
    (u'r', u'Read Only'),
    (u'rw', u'Read & Write')
)

class ConsumerProfile(models.Model):
    user = models.ForeignKey(User)
    key = models.CharField(max_length=200, unique=True)
    secret = models.CharField(max_length=200)
    callback_url = models.URLField(max_length=200, verbose_name = u'Callback URL')
    app_name = models.CharField(max_length=200, verbose_name = u'Name')
    app_url = models.URLField(max_length=200, verbose_name = u'Application Website')
    app_desc = models.CharField(max_length=200, blank=True, verbose_name = u'Description')
    app_type = models.CharField(max_length=5, choices=APP_TYPES, default='b', verbose_name = u'Type of Application')
    permissions = models.CharField(max_length=5, choices=PERMISSIONS, default='r', verbose_name = u'Permissions')

class Token(models.Model):
    key = models.CharField(max_length=200)
    secret = models.CharField(max_length=200)
    callback_url = models.CharField(max_length=200, blank=True)
    verifier = models.CharField(max_length=200, blank=True)
