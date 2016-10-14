from __future__ import unicode_literals
from django.utils.encoding import python_2_unicode_compatible
from django.db import models
from django.utils.translation import ugettext_lazy as _
from accounts.conf import settings
from accounts.managers import EmailAddressManager
from accounts.fields import TimeZoneField

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

