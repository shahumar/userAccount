from __future__ import unicode_literals

import django.dispatch

user_signed_up = django.dispatch.Signal(providing_args=['user', 'form'])
email_confirmation_sent = django.dispatch.Signal(providing_args=['confirmation'])
email_confirmed = django.dispatch.Signal(providing_args=['email_address'])

