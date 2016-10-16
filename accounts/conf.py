from __future__ import unicode_literals
import importlib
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from appconf import AppConf
from accounts.timezones import TIMEZONES



def load_path_attr(path):
    i = path.rfind('.')
    module, attr = path[:i], path[i+1:]
    try:
        mod = importlib.import_module(module)
    except ImportError as e:
        raise ImproperlyConfigured("Error importing {0}: '{1}'".format(module, e))
    try:
        attr = getattr(mod, attr)
    except AttributeError:
        raise ImproperlyConfigured("Module '{0}' does not define a '{1}'".format(module,attr))
    return attr
        
        


class AccountsAppconf(AppConf):
    LOGIN_URL = 'login'
    LOGOUT_URL = "logout"
    SIGNUP_REDIRECT_URL = "/"
    LOGIN_REDIRECT_URL = "/"
    LOGOUT_REDIRECT_URL = "/"
    EMAIL_UNIQUE = True
    EMAIL_CONFIRMATION_EMAIL = True
    EMAIL_CONFIRMATION_URL = 'account_confirm_email'
    EMAIL_CONFIRMATION_EXPIRE_DAYS = 3
    EMAIL_CONFIRMATION_AUTHENTICATED_REDIRECT_URL = None
    EMAIL_CONFIRMATION_ANONYMOUS_REDIRECT_URL = 'account_login'
    TIMEZONES = TIMEZONES
    PASSWORD_USE_HISTORY = True
    HOOKSET = "accounts.hooks.AccountDefaultHookSet"

    def configure_hookset(self, value):
        return load_path_attr(value)()

    

    class Meta:
        prefix = 'account'
