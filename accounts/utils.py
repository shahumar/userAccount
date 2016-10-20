import functools

try:
    from urllib.parse import urlparse,  urlunparse
except ImportError:
    from urlparse import urlparse, urlunparse

from django.core.exceptions import SuspiciousOperation
from django.core import urlresolvers
from django.contrib.auth import get_user_model
from django.http import QueryDict, HttpResponseRedirect


def get_user_lookup_kwargs(kwargs):
    result = {}
    username_field = getattr(get_user_model(), "USERNAME_FIELD", "username")
    for key, value in kwargs.items():
        result[key.format(username=username_field)] = value
    return result

def default_redirect(request, fallback_url, **kwargs):
    redirect_field_name = kwargs.get('redirect_field_name', 'next')
    next_url = request.POST.get(redirect_field_name, request.GET.get(redirect_field_name))
    if not next_url:
        if hasattr(request,  'session'):
            session_key_value = kwargs.get('session_key_value', 'redirect_to')
            if session_key_value in request.session:
                next_url = request.session[session_key_value]
                del request.session[session_key_value]
    is_safe = functools.partial(ensure_safe_url, allowed_protocols = kwargs.get('allowed_protocols'), allowed_host=request.get_host())
    if next_url and is_safe(next_url):
        return next_url
    else:
        try:
            fallback_url = urlresolvers.reverse(fallback_url)
        except urlresolvers.NoReverseMatch:
            if callable(fallback_url):
                raise
            if '/' not in fallback_url and '.' not in fallback_url:
                raise
        is_safe(fallback_url, raise_on_fail=True)
        return fallback_url

def ensure_safe_url(url, allowed_protocols=None, allowed_host=None, raise_on_fail=False):
    if allowed_protocols is None:
        allowed_protocols = ['http', 'https']
    parsed = urlparse(url)
    safe = True
    if parsed.scheme and parsed.scheme not in allowed_protocols:
        if raise_on_fail:
            raise SuspiciousOperation("unsafe redirect to url with protocol '{0}'".format(parsed.scheme))
        safe = False
    if allowed_host and parsed.netloc and parsed.netloc != allowed_host:
        if raise_on_fail:
            raise SuspiciousOperation("unsafe redirect to url with protocol '{0}'".format(parsed.scheme))
        safe = False
    return safe


def get_form_data(form, field_name, default=None):
    if form.prefix:
        key = '-'.join([form.prefix,field_name])
    else:
        key = field_name
    return form.data.get(key, default)

def handle_redirect_to_login(request, **kwargs):
    login_url = kwargs.get('login_url')
    redirect_field_name = kwargs.get('redirect_field_name')
    next_url = kwargs.get('next_url')
    if login_url is None:
        login_url = settings.ACCOUNT_LOGIN_URL
    if next_url is None:
        next_url = request.get_full_path()
    try:
        login_url = urlresolvers.reverse(login_url)
    except urlresolvers.NoReverseMatch:
        if callable(login_url):
            raise
        if '/' not in login_url and '.' not in login_url:
            raise

    url_bits = list(urlparse(login_url))
    if redirect_field_name:
        querystring = QueryDict(url_bits[4], mutable=True)
        querystring[redirect_field_name] = next_url
        url_bits[4] = querystring.urlencode(safe='/')

    return HttpResponseRedirect(urlunparse(url_bits))

