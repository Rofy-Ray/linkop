from django import template
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes

register = template.Library()

@register.filter
def encrypt_id(id):
    return urlsafe_base64_encode(force_bytes(id))
