from django import forms
from django.utils.translation import ugettext_lazy as _

class SignupForm(forms.Form):
    username = forms.CharField(label=_("Username"),  max_length=30, widget=forms.TextInput(), required=True)
    password = forms.CharField(label=_("password"), widget=forms.PasswordInput(render_value=False))
    password_confirm = forms.CharField(label=_("Password (again)"), widget=forms.PasswordInput(render_value=False))
    email = forms.EmailField(label=_("Email"), widget=forms.TextInput(), required=True)
    code = forms.CharField(max_length=64, required=False, widget=forms.HiddenInput())

