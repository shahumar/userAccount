import re
try:
    from collections import OrderedDict
except ImportError:
    OrderedDict = None
from django import forms
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth import get_user_model

from accounts.utils import get_user_lookup_kwargs

alnum_re = re.compile('^\w+$')


class SignupForm(forms.Form):
    username = forms.CharField(label=_("Username"),  max_length=30, widget=forms.TextInput(), required=True)
    password = forms.CharField(label=_("password"), widget=forms.PasswordInput(render_value=False))
    password_confirm = forms.CharField(label=_("Password (again)"), widget=forms.PasswordInput(render_value=False))
    email = forms.EmailField(label=_("Email"), widget=forms.TextInput(), required=True)
    code = forms.CharField(max_length=64, required=False, widget=forms.HiddenInput())

    def clean_username(self):
        if not alnum_re.search(self.cleaned_data['username']):
            raise forms.ValidationError(_("Usernames can only contains letters, numbers and underscores"))

        User = get_user_model()
        lookup_kwargs = get_user_lookup_kwargs({
            "{username}__iexact": self.cleaned_data['username']    
        })
        qs = User.objects.filter(**lookup_kwargs)
        if not qs.exists():
            return self.cleaned_data['username']
        raise forms.ValidationError(_("Username already exists"))


class LoginForm(forms.Form):
    password = forms.CharField(label=_("password"), widget=forms.PasswordInput(render_value=False))
    remember = forms.BooleanField(label=_("Remember me"), required=False)
    user = None

    def clean(self):
        pass

class LoginUsernameForm(LoginForm):
    username = forms.CharField(label=_('username'), max_length=30)
    authentication_fail_message = _("The username or password you specify are not correct")
    identifier_field = 'username'

    def __init__(self, *args, **kwargs):
        super(LoginUsernameForm, self).__init(*args, **kwargs)
        field_order = ['username', 'password', 'remember']
        if not OrderedDict or hasattr(self.fields,'keyOrder'):
            self.fields.keyOrder = field_order
        else:
            self.fields = OrderedDict((k,self.fields[k]) for k in field_order)

