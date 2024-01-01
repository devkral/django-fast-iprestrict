import ipaddress
import re

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import MinLengthValidator


def validate_network(value):
    try:
        ip_addr = ipaddress.ip_address(value, strict=False)
        if getattr(ip_addr, "ipv4_mapped", None):
            raise ValidationError(
                "Mapped ip4 addresses are forbidden. Use ip4 address instead.",
                code="invalid",
                params={"value": value},
            )
        # skip further checks, as every ip is also a network
        return
    except ValueError:
        pass
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


min_length_1 = MinLengthValidator(1)


def validate_ratelimit_key(value):
    min_length_1(value)
    if value == "django_fast_iprestrict.apply_iprestrict":
        raise ValidationError(
            "ratelimit key would cause infinite recursion",
            code="insecure",
            params={"value": value},
        )
    splitted = value.split(".")
    if not all(map(lambda x: x.isidentifier(), splitted)):
        raise ValidationError("Invalid path.", code="invalid", params={"value": value})
    if splitted[-1].startswith("_"):
        raise ValidationError(
            "not a safe ratelimit key.", code="insecure", params={"value": value}
        )

    for prefix in getattr(settings, "IPRESTRICT_ALLOWED_FN_PREFIXES", ()):
        if value.startswith(prefix):
            return
    if not value.isidentifier():
        raise ValidationError(
            "not a safe ratelimit key.", code="insecure", params={"value": value}
        )


def validate_generator_fn(value):
    min_length_1(value)
    # TODO: expand security checks
    splitted = value.split(".")
    if not all(map(lambda x: x.isidentifier(), splitted)):
        raise ValidationError("Invalid path.", code="invalid", params={"value": value})
    if splitted[-1].startswith("_"):
        raise ValidationError(
            "not a safe generate_fn.", code="insecure", params={"value": value}
        )

    for prefix in getattr(settings, "IPRESTRICT_ALLOWED_FN_PREFIXES", ()):
        if value.startswith(prefix):
            return
    raise ValidationError(
        "not a safe generate_fn.", code="insecure", params={"value": value}
    )


_rate = re.compile(r"(\d+)/(\d+)?([smhdw])?")


def validate_rate(value):
    matched = _rate.match(value)
    if not matched:
        raise ValidationError("Invalid rate", code="invalid", params={"value": value})
