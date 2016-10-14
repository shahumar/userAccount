from __future__ import unicode_literals
from django.conf import settings
from appconf import AppConf
from accounts.timezones import TIMEZONES

class AccountsAppconf(AppConf):
    LOGIN_URL = 'login'
    LOGOUT_URL = "logout"
    SIGNUP_REDIRECT_URL = "/"
    LOGIN_REDIRECT_URL = "/"
    LOGOUT_REDIRECT_URL = "/"
    EMAIL_UNIQUE = True
    ACCOUNT_TIMEZONES = TIMEZONES

    class Meta:
        prefix = 'account'
