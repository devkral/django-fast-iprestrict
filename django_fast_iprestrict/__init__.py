__all__ = ["apply_iprestrict"]

import asyncio
from functools import partial, singledispatch

from django.http import HttpRequest

from .utils import RULE_ACTION, get_default_action, get_ip

try:
    import django_fast_ratelimit as ratelimit
except ImportError:
    ratelimit = None

if ratelimit:

    def _apply_iprestrict(
        request,
        group,
        action=None,
        ignore_pathes=False,
        require_rule=False,
    ):
        # don't check methods here as the check is done in ratelimit
        from .models import Rule, RulePath

        rule = Rule.objects.filter(name=group).first()
        if not rule:
            if require_rule:
                return 1
            return int(get_default_action() == RULE_ACTION.deny)
        with_path = False
        ip = get_ip(request)
        if not ignore_pathes:
            with_path = rule.id in RulePath.objects.path_matchers()
        if with_path:
            action, _, ratelimits = RulePath.objects.match_ip_and_path(
                ip=ip, path=request.path, rule_id=rule.id
            )[1:]
        else:
            action, _, ratelimits = rule.match_ip(ip=ip)[1:]

        for rdict in ratelimits:
            r = ratelimit.get_ratelimit(
                request=request,
                action=ratelimit.Action(rdict["action"]),
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

    async def _aapply_iprestrict(
        request,
        group,
        action=None,
        ignore_pathes=False,
        require_rule=False,
    ):
        # don't check methods here as the check is done in ratelimit
        from .models import Rule, RulePath

        rule = await Rule.objects.filter(name=group).afirst()
        if not rule:
            if require_rule:
                return 1
            return int(get_default_action() == RULE_ACTION.deny)
        with_path = False
        ip = get_ip(request)
        if not ignore_pathes:
            with_path = rule.id in await RulePath.objects.apath_matchers()
        if with_path:
            action, _, ratelimits = (
                await RulePath.objects.amatch_ip_and_path(
                    ip=ip, path=request.path, rule_id=rule.id
                )
            )[1:]
        else:
            action, _, ratelimits = (await rule.amatch_ip(ip=ip))[1:]
        for rdict in ratelimits:
            r = await ratelimit.aget_ratelimit(
                request=request,
                action=ratelimit.Action(rdict["action"]),
                group=rdict["group"],
                key=rdict["key"],
                rate=rdict["rate"],
            )
            await r.adecorate_object(
                request,
                name=rdict["decorate_name"],
                wait=rdict["wait"],
                block=rdict["block"],
            )
        if action == RULE_ACTION.deny.value:
            return 1
        return 0

    @singledispatch
    def apply_iprestrict(request, group, action=None, **kwargs):
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop:
            return _aapply_iprestrict(request, group, action, **kwargs)
        else:
            return _apply_iprestrict(request, group, action, **kwargs)

    @apply_iprestrict.register(str)
    def _(arg: str = ""):
        args = arg.split(",")
        return partial(
            apply_iprestrict.dispatch(HttpRequest),
            ignore_pathes="ignore_pathes" in args,
            require_rule="require_rule" in args,
        )

else:

    def apply_iprestrict(*args, **kwargs):
        raise ImportError("ratelimit not installed")
