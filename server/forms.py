from django.forms import ModelForm
from server.models import *

class ConsumerRegisterForm(ModelForm):
    class Meta:
        model = ConsumerProfile
        exclude = [u'key', u'secret', u'user']
