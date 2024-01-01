from functools import partial, singledispatch

from django.http import HttpRequest

from .utils import RULE_ACTION, get_default_action, get_ip

try:
    import django_fast_ratelimit as ratelimit
except ImportError:
    ratelimit = None


@singledispatch
def apply_iprestrict(request: HttpRequest, group, ignore_pathes=False):
    from .models import Rule, RulePath

    rule = Rule.objects.filter(name=group).first()
    if not rule:
        return int(get_default_action() == RULE_ACTION.deny)
    with_path = False
    ip = get_ip(request)
    if not ignore_pathes:
        with_path = rule.id in RulePath.objects.path_matchers()
    if with_path:
        action, _, ratelimits = RulePath.objects.match_ip_and_path(
            ip=ip, path=request.path
        )[1:]
    else:
        action, _, ratelimits = rule.match_ip(ip=ip)[1:]
    if ratelimit:
        for rdict in ratelimits:
            r = ratelimit.get_ratelimit(
                request=request,
                action=ratelimit.Action.INCREASE,
                group=rdict["group"],
                key=rdict["key"],
                rate=rdict["rate"],
            )
            r.decorate_object(
                request, name=rdict["decorate_name"], block=rdict["block"]
            )

    if action == RULE_ACTION.deny.value:
        return 1

    return 0


@apply_iprestrict.register
def _(arg: str = ""):
    return partial(apply_iprestrict, ignore_pathes=arg == "ignore_pathes")
