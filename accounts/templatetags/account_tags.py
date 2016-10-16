from __future__ import unicode_literals

from django import template
from django.template.defaulttags import URLNode 
from django.template.base import kwarg_re
from django.utils.http import urlencode

register = template.Library()


class URLNextNode(URLNode):
    def add_next(self, url, context):
        if all([key in context for key in ['redirect_field_name', 'redirect_field_value']]):
            if context['redirect_field_value']:
                url += '?' + urlencode({context['redirect_field_name']: context['redirect_field_value']})

        return url

    def render(self,context):
        url = super(URLNextNode, self).render(context)
        if self.asvar:
            url = context[self.asvar]
        url = self.add_next(url, context)
        if self.asvar:
            context[self.asvar] = url
            return ""
        else:
            return url

@register.tag
def urlnext(parser, token):
    bits = token.split_contents()
    if len(bits) < 2:
        raise template.TemplateSyntaxError("'%s' takes at least one argument (path to a view)" % bits[0])
    viewname = parser.compile_filter(bits[1])
    args = []
    kwargs = {}
    asvar = None
    bits = bits[2:]
    if len(bits) >= 2 and bits[-2] == 'as':
        asvar = bits[-1]
        bits = bits[:-2]

    if len(bits):
        for bit in bits:
            match = kwarg_re.match(bit)
            if not match:
                raise template.TemplateSyntaxError('Malformed arguments to url tag')
            name, value = match.groups()
            if name:
                kwargs[name] = parser.compile_filter(value)
            else:
                args.append(parser.compile_filter(value))
    return URLNextNode(viewname, args, kwargs, asvar)

