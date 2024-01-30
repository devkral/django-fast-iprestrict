__all__ = ["apply_iprestrict"]

import asyncio
from functools import partial, singledispatch

from django.http import HttpRequest

from .utils import RULE_ACTION, get_ip

try:
    import django_fast_ratelimit as ratelimit
except ImportError:
    ratelimit = None

if ratelimit:

    def _apply_iprestrict(
        request,
        group,
        action=None,
        rate=None,
        ignore_pathes=False,
        require_rule=False,
        execute_only=False,
        count_only=False,
    ):
        # don't check methods here as the check is done in ratelimit
        from .models import Rule, RulePath, RuleRatelimitGroup

        ip = get_ip(request)
        with_path = False
        if not ignore_pathes:
            name_has_pathes = RuleRatelimitGroup.objects.name_matchers()[1]
            with_path = group in name_has_pathes
        if with_path:
            rule_id, action, _, ratelimits = RulePath.objects.match_ip_and_path(
                ip=ip, path=request.path, ratelimit_group=group
            )
        else:
            rule_id, action, _, ratelimits = Rule.objects.match_ip(
                ip=ip, ratelimit_group=group
            )
        if rule_id is None and require_rule:
            raise ratelimit.Disabled(
                "no rule found for %s" % group,
                ratelimit=ratelimit.Ratelimit(group=group, request_limit=1, end=0),
            )

        for rdict in ratelimits:
            if rdict["rate"] == "inherit":
                r_rate = rate
                if not r_rate:
                    continue
            else:
                r_rate = rdict["rate"]
            r = ratelimit.get_ratelimit(
                request=request,
                action=ratelimit.Action.PEEK if execute_only else rdict["action"],
                group=rdict["group"],
                key=rdict["key"],
                rate=r_rate,
            )
            r.decorate_object(
                request,
                name=rdict["decorate_name"],
                block=rdict["block"] and not count_only,
            )
        if action == RULE_ACTION.deny and not count_only:
            return 1
        return 0

    async def _aapply_iprestrict(
        request,
        group,
        action=None,
        rate=None,
        ignore_pathes=False,
        require_rule=False,
        execute_only=False,
        count_only=False,
    ):
        # don't check methods here as the check is done in ratelimit
        from .models import Rule, RulePath, RuleRatelimitGroup

        ip = get_ip(request)

        with_path = False
        if not ignore_pathes:
            name_has_pathes = (await RuleRatelimitGroup.objects.aname_matchers())[1]
            with_path = group in name_has_pathes
        if with_path:
            rule_id, action, _, ratelimits = await RulePath.objects.amatch_ip_and_path(
                ip=ip, path=request.path, ratelimit_group=group
            )
        else:
            rule_id, action, _, ratelimits = await Rule.objects.amatch_ip(
                ip=ip, ratelimit_group=group
            )
        if rule_id is None and require_rule:
            raise ratelimit.Disabled(
                "no rule found for %s" % group,
                ratelimit=ratelimit.Ratelimit(group=group, request_limit=1, end=0),
            )
        for rdict in ratelimits:
            if rdict["rate"] == "inherit":
                r_rate = rate
                if not r_rate:
                    continue
            else:
                r_rate = rdict["rate"]
            r = await ratelimit.aget_ratelimit(
                request=request,
                action=ratelimit.Action.PEEK if execute_only else rdict["action"],
                group=rdict["group"],
                key=rdict["key"],
                rate=r_rate,
            )
            await r.adecorate_object(
                request,
                name=rdict["decorate_name"],
                wait=rdict["wait"] and not count_only,
                block=rdict["block"] and not count_only,
            )
        if action == RULE_ACTION.deny and not count_only:
            return 1
        return 0

    @singledispatch
    def apply_iprestrict(request, group, action=None, rate=None, **kwargs):
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop:
            return _aapply_iprestrict(request, group, action, rate, **kwargs)
        else:
            return _apply_iprestrict(request, group, action, rate, **kwargs)

    @apply_iprestrict.register(str)
    def _(arg: str = "", *args):
        args = list(args)
        args.extend(arg.split(","))
        return partial(
            apply_iprestrict.dispatch(HttpRequest),
            ignore_pathes="ignore_pathes" in args,
            require_rule="require_rule" in args,
            execute_only="execute_only" in args,
            count_only="count_only" in args,
        )

else:

    def apply_iprestrict(*args, **kwargs):
        raise ImportError("ratelimit not installed")
