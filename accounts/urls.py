from __future__ import unicode_literals

from django.conf.urls import url
from accounts.views import SignupView

urlpatterns = [
    url(r'^signup/$', SignupView.as_view(), name='signup'),        
]
