from functools import partial, singledispatch

from django.http import HttpRequest

from .utils import RULE_ACTION, get_default_action, get_ip


@singledispatch
def apply_iprestrict(request: HttpRequest, group, ignore_pathes=False):
    from .models import Rule, RulePath

    rule = Rule.objects.filter(name=group).first()
    if not rule:
        return int(get_default_action() == RULE_ACTION.deny.value)
    with_path = False
    if not ignore_pathes:
        with_path = rule.id in RulePath.objects.path_matchers()
    if with_path:
        if (
            RulePath.objects.match_ip_and_path(ip=get_ip(request), path=request.path)[1]
            == RULE_ACTION.deny.value
        ):
            return 1

    else:
        if rule.match_ip(ip=get_ip(request))[1] == RULE_ACTION.deny.value:
            return 1

    return 0


@apply_iprestrict.register
def _(arg: str = ""):
    return partial(apply_iprestrict, ignore_pathes=arg == "ignore_pathes")
