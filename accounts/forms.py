import re
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

