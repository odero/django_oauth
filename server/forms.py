from django.forms import ModelForm
from models import *

class ConsumerRegisterForm(ModelForm):
    class Meta:
        model = ConsumerProfile
        exclude = [u'key', u'secret', u'user']
