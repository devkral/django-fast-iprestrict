from django.conf import settings
from django.http import HttpRequest

from .utils import get_ip


def apply_iprestrict(request: HttpRequest, group):
    from .models import Rule

    rule = Rule.objects.filter(name=group).first()
    if not rule:
        return int(getattr(settings, "IPRESTRICT_DEFAULT_ACTION", "a") == "b")
    if rule.match_ip(get_ip(request), return_action=True) == "b":
        return 1

    return 0
