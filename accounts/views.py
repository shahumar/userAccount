from django.shortcuts import render, redirect
from django.views.generic.edit import FormView
from django.contrib import messages
from django.contrib.sites.shortcuts import get_current_site
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth.hashers import make_password
from django.conf import settings
from django.contrib.auth import get_user_model
from django.views.generic.base import View, TemplateResponseMixin

from accounts.utils import default_redirect
from accounts.models import EmailAddress, Account, PasswordHistory, EmailConfirmation
from accounts import signals
from accounts.hooks import hookset
from accounts.forms import SignupForm


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

    def create_password_history(self, form, user):
        if settings.ACCOUNT_PASSWORD_USE_HISTORY:
            password = form.cleaned_data[self.form_password_field]
            PasswordHistory.objects.create(user=user, password=make_password(password))



class SignupView(PasswordMixin, FormView):
    template_name = 'signup.html'
    form_class = SignupForm
    fallback_url_setting = 'ACCOUNT_SIGNUP_REDIRECT_URL'
    form_password_field = 'password'

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

    def get_initial(self):
        initial = super(SignupView, self).get_initial()
        if self.signup_code:
            initial['code'] = self.signup_code.code
            if self.signup_code.email:
                initial['email'] = self.signup_code.email
        return initial

    def form_invalid(self, form):
        raise Exception(form)
    
    def form_valid(self, form):
        self.created_user = self.create_user(form, commit=False)
        self.created_user._disable_account_creation = True
        self.created_user.save()
        self.use_signup_code(self.created_user)
        email_address = self.create_email_address(form)
        if settings.ACCOUNT_EMAIL_CONFIRMATION_REQUIRED and not email_address.verified:
            self.created_user.is_active = False
            self.created_user.save()
        self.create_account(form)
        self.create_password_history(form, self.created_user)
        self.after_signup(form)
        if settings.ACCOUNT_EMAIL_CONFIRMATION_EMAIL and not email_address.verified:
            self.send_email_confirmation(email_address)

        raise Exception(form)

    def send_email_confirmation(self, email_address):
        email_address.send_confirmation(site=get_current_site(self.request))

    def after_signup(self, form):
        signals.user_signed_up.send(sender=SignupForm, user=self.created_user, form=form)

    def create_account(self, form):
        return Account.create(request=self.request,user=self.created_user, create_email=False)

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

    def create_email_address(self, form, **kwargs):
        kwargs.setdefault("primary", True)
        kwargs.setdefault("verified", False)
        if self.signup_code:
            kwargs['verified'] = self.created_user.email == self.signup_code.email if self.signup_code.email else False
        return EmailAddress.objects.add_email(self.created_user, self.created_user.email, **kwargs)



class ConfirmEmailView(TemplateResponseMixin, View):
    http_method_names = ['get', 'post']
    messages = {
        "email_confirmed":{"level": messages.SUCCESS, "text": _("You have confirmed")}    
    }

    def get_template_names(self):
        return {
            "GET": ["accounts/email_confirm.html"],
            "POST": ["accounts/email_confirmed.html"]
        }[self.request.method]

    def get(self, *args, **kwargs):
        self.object = self.get_object()
        ctx = self.get_context_data()
        return self.render_to_response(ctx)

    def post(self, *args, **kwargs):
        self.object = confirmation = self.get_object()
        confirmation.confirm()
        self.after_confirmation(confirmation)
        redirect_url = self.get_redirect_url()
        if not redirect_url:
            ctx = self.get_context_data()
            return self.render_to_response(ctx)
        if self.messages.get('email_confirmed'):
            messages.add_message(self.request, self.messages['email_confirmed']['level'], self.messages['email_confirmed']['text'].format(**{'email': confirmation.email_address.email}))
        return redirect(redirect_url)

    def get_redirect_url(self):
        if self.request.user.is_authenticated():
            if not settings.ACCOUNT_EMAIL_CONFIRMATION_AUTHENTICATED_REDIRECT_URL:
                return settings.ACCOUNT_LOGIN_REDIECT_URL
            return settings.ACCOUNT_EMAIL_CONFIRMATION_AUTHENTICATED_REDIRECT_URL
        else:
            return settings.ACCOUNT_EMAIL_CONFIRMATION_ANONYMOUS_REDIRECT_URL

    def after_confirmation(self, confirmation):
        user = confirmation.email_address.user
        user.is_active = True
        user.save()


    def get_object(self, queryset=None):
        if queryset is None:
            queryset = self.get_queryset()
            try:
                return queryset.get(key=self.kwargs['key'].lower())
            except EmailConfirmation.DoesNotExist:
                raise Http404()
    
    def get_queryset(self):
        qs = EmailConfirmation.objects.all()
        qs = qs.select_related('email_address__user')
        return qs

    def get_context_data(self, **kwargs):
        ctx = kwargs
        ctx['confirmation'] = self.object
        return ctx
