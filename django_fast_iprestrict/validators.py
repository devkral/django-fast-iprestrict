import ipaddress
import re

from django.core.exceptions import ValidationError


def validate_network(value):
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise ValidationError(
            'Enter a valid IPv4 or IPv6 network or "*".',
            code="invalid",
            params={"value": value},
        )


def validate_regex(value):
    try:
        re.compile(value)
    except re.error:
        raise ValidationError("Invalid regex.", code="invalid", params={"value": value})


def validate_generator_fn(value):
    # TODO: expand with security checks
    if not all(lambda x: x.isidentifier(), value.split(".", "")):
        raise ValidationError("Invalid path.", code="invalid", params={"value": value})
    if not value.endswith("iprestrict_gen"):
        raise ValidationError(
            "not a valid generator function.", code="invalid", params={"value": value}
        )
