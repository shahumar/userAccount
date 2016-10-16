import hashlib
import random

from django.core.mail import send_mail
from django.template.loader import render_to_string

from accounts.conf import settings


class AccountDefaultHookSet(object):
    
    def send_confirmation_email(self, to, ctx):
        subject = render_to_string('accounts/email/email_confirmation_subject.txt', ctx)
        subject = "".join(subject.splitlines())

        message = render_to_string('accounts/email/email_confirmation_message.txt', ctx)
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, to)

    def generate_email_confirmation_token(self, email):
        return self.generate_random_token([email])

    def generate_random_token(self, extra=None, hash_func=hashlib.sha256):
        if extra is None:
            extra = []
        bits = extra + [str(random.SystemRandom().getrandbits(512))]
        return hash_func("".join(bits).encode('utf-8')).hexdigest()



class HookProxy(object):
    def __getattr__(self, attr):
        return getattr(settings.ACCOUNT_HOOKSET, attr)

hookset = HookProxy()


