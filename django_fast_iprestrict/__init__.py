from django.http import HttpRequest

from .utils import RULE_ACTION, get_default_action, get_ip


def apply_iprestrict(request: HttpRequest, group):
    from .models import Rule

    rule = Rule.objects.filter(name=group).first()
    if not rule:
        return int(get_default_action() == RULE_ACTION.deny.value)
    if rule.match_ip(get_ip(request))[1] == RULE_ACTION.deny.value:
        return 1

    return 0
