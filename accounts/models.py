from __future__ import unicode_literals
import datetime
from django.utils.encoding import python_2_unicode_compatible
from django.db import models
from django.utils.translation import ugettext_lazy as _
from django.utils import timezone, translation
from django.core.urlresolvers import reverse

from accounts.conf import settings
from accounts.managers import EmailAddressManager, EmailConfirmationManager
from accounts.fields import TimeZoneField
from accounts.hooks import hookset
from accounts import signals

@python_2_unicode_compatible
class EmailAddress(models.Model):

    user = models.ForeignKey(settings.AUTH_USER_MODEL)
    email = models.EmailField(max_length=254, unique=settings.ACCOUNT_EMAIL_UNIQUE)
    verified = models.BooleanField(_("verified"), default=False)
    primary = models.BooleanField(_("primary"), default=False)

    objects = EmailAddressManager()

    class Meta:
        verbose_name = _("email address")
        verbose_name_plural = _("email addresses")
        if not settings.ACCOUNT_EMAIL_UNIQUE:
            unique_together = ('user', 'email')



    def __str__(self):
        return self.email

    def send_confirmation(self, **kwargs):
        confirmation = EmailConfirmation.create(self)
        confirmation.send(**kwargs)
        return confirmation

    def set_as_primary(self, conditional=False):
        old_primary =   EmailAddress.objects.get_primary(self.user)
        if old_primary:
            if conditional:
                return False
            old_primary.primary = False
            old_primary.save()
        self.primary = True
        self.save()
        self.user.email = self.email
        self.user.save()
        return True


@python_2_unicode_compatible
class EmailConfirmation(models.Model):
    email_address = models.ForeignKey(EmailAddress)
    created = models.DateTimeField(default=timezone.now)
    sent = models.DateTimeField(null=True)
    key = models.CharField(max_length=64, unique=True)

    objects = EmailConfirmationManager()

    class Meta:
        verbose_name = _("email confirmation")
        verbose_name_plural = _("email confirmations")

    def __str__(self):
        return "confirmation for {0}".format(self.email_address)

    @classmethod
    def create(cls, email_address):
        key = hookset.generate_email_confirmation_token(email_address.email)
        return cls._default_manager.create(email_address=email_address, key=key)

    def send(self, **kwargs):
        current_site = kwargs['site'] if 'site' in kwargs else Site.objects.get_current()
        protocol = getattr(settings, 'DEFAULT_HTTP_PROTOCOL', 'http')
        activate_url = "{0}://{1}{2}".format(protocol, current_site.domain, reverse(settings.ACCOUNT_EMAIL_CONFIRMATION_URL, args=[self.key]))
        ctx = {"email_address": self.email_address, "user": self.email_address.user, "activate_url": activate_url, "current_site": current_site, "key": self.key}
        hookset.send_confirmation_email([self.email_address.email], ctx)
        self.sent = timezone.now()
        self.save()
        signals.email_confirmation_sent.send(sender=self.__class__, confirmation=self)

    def key_expired(self):
        expiration_date = self.sent + datetime.timedelta(days=settings.ACCOUNT_EMAIL_CONFIRMATION_EXPIRE_DAYS)
        return expiration_date <= timezone.now()
    key_expired.boolean = True
    
    def confirm(self):
        if not self.key_expired() and not self.email_address.verified:
            email_address = self.email_address
            email_address.verified = True
            email_address.set_as_primary(conditional=True)
            email_address.save()
            signals.email_confirmed.send(sender=self.__class__, email_address=email_address)
            return email_address


@python_2_unicode_compatible
class Account(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='account', verbose_name=_('user'))
    timezone = TimeZoneField(_("timezone"))
    language = models.CharField(_('language'), max_length=10, choices=settings.ACCOUNT_LANGUAGES, default=settings.LANGUAGE_CODE)

    @classmethod
    def create(cls,  request=None, **kwargs):
        create_email = kwargs.pop('create_email', True)
        confirm_email = kwargs.pop('confirm_email', None)
        account = cls(**kwargs)
        if 'language' not in kwargs:
            if request is None:
                account.language = settings.LANGUAGE_CODE
            else:
                account.language = translation.get_language_from_request(request, check_path=True)
        account.save()
        if create_email and account.user.email:
            kwargs = {'primary': True}
            if confirm_email is not None:
                kwargs['confirm_email'] = confirm_email
            EmailAddress.objects.add_email(account.user, account.user.email, **kwargs)
        return account

    def __str__(self):
        return str(self.user)


@python_2_unicode_compatible
class PasswordHistory(models.Model):
    
    class Meta:
        verbose_name = _("Password History")
        verbose_name_plural = _("password histories")

    user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='password_history')
    password = models.CharField(max_length=255)
    timestamp = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.user.email
