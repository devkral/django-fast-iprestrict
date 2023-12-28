import functools
import re

from django.conf import settings
from django.db import models
from django.http import HttpRequest


class invertedset(frozenset):
    def __contains__(self, item):
        return not super().__contains__(item)


class RULE_ACTION(models.TextChoices):
    allow = ("a", "allow")
    deny = ("b", "deny")
    disabled = ("c", "disabled")


@functools.lru_cache(maxsize=1)
def get_TRUSTED_PROXY() -> frozenset:
    setting = getattr(settings, "IPRESTRICT_TRUSTED_PROXIES", None)
    if not setting:
        setting = getattr(settings, "RATELIMIT_TRUSTED_PROXIES", ["unix"])
    if setting == "all":
        return invertedset()
    else:
        return frozenset(setting)


def get_FALLBACK() -> str:
    setting = getattr(settings, "IPRESTRICT_TESTCLIENT_FALLBACK", None)
    if not setting:
        setting = getattr(settings, "RATELIMIT_TESTCLIENT_FALLBACK", "::1")
    return setting


_forwarded_regex = re.compile(r'for="?([^";, ]+)', re.IGNORECASE)
_http_x_forwarded_regex = re.compile(r'[ "]*([^";, ]+)')
_ip6_port_cleanup_regex = re.compile(r"(?<=\]):[0-9]+$")
_ip4_port_cleanup_regex = re.compile(r":[0-9]+$")


def get_ip(request: HttpRequest):
    client_ip = request.META.get("REMOTE_ADDR", "") or "unix"
    if client_ip in get_TRUSTED_PROXY():
        try:
            ip_matches = _forwarded_regex.search(request.META["HTTP_FORWARDED"])
            client_ip = ip_matches[1]
        except KeyError:
            try:
                ip_matches = _http_x_forwarded_regex.search(
                    request.META["HTTP_X_FORWARDED_FOR"]
                )
                client_ip = ip_matches[1]
            except KeyError:
                pass
    if client_ip == "testclient":  # starlite test client
        client_ip = get_FALLBACK()
    if client_ip in {"unix", "invalid"}:
        raise ValueError("Could not determinate ip address")
    if "." in client_ip and client_ip.count(":") <= 1:
        client_ip = _ip4_port_cleanup_regex.sub("", client_ip)
    else:
        client_ip = _ip6_port_cleanup_regex.sub("", client_ip).strip("[]")

    return client_ip


def get_default_action():
    action = RULE_ACTION[getattr(settings, "IPRESTRICT_DEFAULT_ACTION", "allow")]
    assert action != RULE_ACTION.disabled, "disabled is not a valid default action"
    return action.value
