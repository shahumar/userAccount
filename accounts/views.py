from django.shortcuts import render
from django.views.generic.edit import FormView
from django.contrib import messages
from django.utils.translation import ugettext_lazy as _
from accounts.forms import SignupForm
from django.conf import settings
from django.contrib.auth import get_user_model
from accounts.utils import default_redirect

class PasswordMixin(object):
    redirect_field_name = 'next'
    messages = {
        "password_changed": {
            "level": messages.SUCCESS,
            "text": _("Password successfully changed")
        }    
    }

    def get_context_data(self, **kwargs):
        ctx = super(PasswordMixin, self).get_context_data(**kwargs)
        redirect_field_name = self.get_redirect_field_name()
        ctx.update(
            {
                "redirect_field_name": redirect_field_name,
                "redirect_field_value": self.request.POST.get(redirect_field_name,self.request.GET.get(redirect_field_name, ''))
            }
        )
        return ctx

    def change_password(self, form):
        user = self.get_user()
        user.set_password(form.cleaned_data[self.form_password_field])
        user.save()
        return user

    def get_redirect_field_name(self):
        return self.redirect_field_name

    def get_success_url(self, fallback_url=None, **kwargs):
        if fallback_url is None:
            fallback_url = getattr(settings, self.fallback_url_setting, None)
        kwargs.setdefault("redirect_field_name", self.get_redirect_field_name())
        return default_redirect(self.request, fallback_url, **kwargs)



class SignupView(PasswordMixin, FormView):
    template_name = 'signup.html'
    form_class = SignupForm
    fallback_url_setting = 'ACCOUNT_SIGNUP_REDIRECT_URL'

    def __init__(self, *args, **kwargs):
        self.created_user = None
        kwargs["signup_code"] = None
        super(SignupView, self).__init__(*args, **kwargs)
    
    def dispatch(self, request, *args, **kwargs):
        self.request = request
        self.args  = args
        self.kwargs = kwargs
        self.setup_signup_code()
        return super(SignupView, self).dispatch(request, *args, **kwargs)

    def setup_signup_code(self):
        code = self.get_code()
        if code:
            try:
                self.signup_code = SignupCode.check_code(code)
            except SignupCode.InvalidCode:
                self.signup_code = None
            self.signup_code_present = True
        else:
            self.signup_code = None
            self.signup_code_present = False

    def get_code(self):
        return self.request.POST.get('code', self.request.GET.get('code'))

    def form_valid(self, form):
        self.created_user = self.create_user(form, commit=False)
        self.created_user._disable_account_creation = True
        self.created_user.save()
        self.use_signup_code(self.created_user)
        email_address = self.create_email_address(form)
        if settings.ACCOUNT_EMAIL_CONFIRMATION_REQUIRED and not email_address.verified:
            self.created_user.is_active = False
            self.created_user.save()

        raise Exception(form)

    def create_user(self, form, commit=True, model=None, **kwargs):
        User = model
        if User is None:
            User = get_user_model()
        user = User(**kwargs)
        username = form.cleaned_data.get('username')
        if username is None:
            username = self.generate_username(form)
        user.username = username
        user.email = form.cleaned_data.get('email').strip()
        password = form.cleaned_data.get('password')
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        if commit:
            user.save()
        return user

    def use_signup_code(self, user):
        if self.signup_code:
            self.signup_code.use(user)
