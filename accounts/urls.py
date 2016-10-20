from __future__ import unicode_literals

from django.conf.urls import url
from accounts.views import SignupView, ConfirmEmailView, LoginView, SettingsView, LogoutView

urlpatterns = [
    url(r'^signup/$', SignupView.as_view(), name='account_signup'),        
    url(r'^login/$', LoginView.as_view(), name='account_login'),        
    url(r'^logout/$', LogoutView.as_view(), name='account_logout'),        
    url(r'^confirm_email/(?P<key>\w+)$', ConfirmEmailView.as_view(), name='account_confirm_email'),        
    url(r'^settings/$', SettingsView.as_view(), name='account_settings'),        
]
