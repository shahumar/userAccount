from __future__ import unicode_literals

from django.conf.urls import url
from accounts.views import SignupView, ConfirmEmailView, LoginView

urlpatterns = [
    url(r'^signup/$', SignupView.as_view(), name='signup'),        
    url(r'^login/$', LoginView.as_view(), name='account_login'),        
    url(r'^confirm_email/(?P<key>\w+)$', ConfirmEmailView.as_view(), name='account_confirm_email'),        
]
