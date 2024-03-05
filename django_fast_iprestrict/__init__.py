__all__ = ["apply_iprestrict"]

import asyncio
from functools import partial, singledispatch
from typing import Optional, Union

from django.http import HttpRequest

from .utils import RATELIMIT_ACTION, RULE_ACTION, get_ip

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
        no_count=False,
        no_execute=False,
        default_action: Optional[Union[str, RULE_ACTION]] = None,
    ):
        # don't check methods here as the check is done in ratelimit
        from .models import Rule, RulePath, RuleRatelimitGroup

        if action == RATELIMIT_ACTION.RESET or action == RATELIMIT_ACTION.RESET_EPOCH:
            no_count = True
            no_execute = True

        ip = get_ip(request)
        with_path = False
        if not ignore_pathes:
            name_has_pathes = RuleRatelimitGroup.objects.name_matchers()[1]
            with_path = group in name_has_pathes
        if with_path:
            rule_id, iprestrict_action, _, ratelimits = (
                RulePath.objects.match_ip_and_path(
                    ip=ip,
                    path=request.path,
                    ratelimit_group=group,
                    default_action=default_action,
                )
            )
        else:
            rule_id, iprestrict_action, _, ratelimits = Rule.objects.match_ip(
                ip=ip,
                ratelimit_group=group,
                default_action=default_action,
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
                action=ratelimit.Action.PEEK if no_count else rdict["action"],
                group=rdict["group"],
                key=rdict["key"],
                rate=r_rate,
            )
            r.decorate_object(
                request,
                name=rdict["decorate_name"],
                block=rdict["block"] and not no_execute,
            )
            if action == RATELIMIT_ACTION.RESET:
                r.reset()
            elif action == RATELIMIT_ACTION.RESET_EPOCH:
                r.reset(request)
        if no_execute and not default_action:
            return 0
        if iprestrict_action == RULE_ACTION.deny:
            return 1
        return 0

    async def _aapply_iprestrict(
        request,
        group,
        action=None,
        rate=None,
        ignore_pathes=False,
        require_rule=False,
        no_count=False,
        no_execute=False,
        default_action: Optional[Union[str, RULE_ACTION]] = None,
    ):
        # don't check methods here as the check is done in ratelimit
        from .models import Rule, RulePath, RuleRatelimitGroup

        if action == RATELIMIT_ACTION.RESET or action == RATELIMIT_ACTION.RESET_EPOCH:
            no_count = True
            no_execute = True

        ip = get_ip(request)

        with_path = False
        if not ignore_pathes:
            name_has_pathes = (await RuleRatelimitGroup.objects.aname_matchers())[1]
            with_path = group in name_has_pathes
        if with_path:
            (
                rule_id,
                iprestrict_action,
                _,
                ratelimits,
            ) = await RulePath.objects.amatch_ip_and_path(
                ip=ip,
                path=request.path,
                ratelimit_group=group,
                default_action=default_action,
            )
        else:
            rule_id, iprestrict_action, _, ratelimits = await Rule.objects.amatch_ip(
                ip=ip,
                ratelimit_group=group,
                default_action=default_action,
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
                action=ratelimit.Action.PEEK if no_count else rdict["action"],
                group=rdict["group"],
                key=rdict["key"],
                rate=r_rate,
            )
            await r.adecorate_object(
                request,
                name=rdict["decorate_name"],
                wait=rdict["wait"] and not no_execute,
                block=rdict["block"] and not no_execute,
            )
            if action == RATELIMIT_ACTION.RESET:
                await r.areset()
            elif action == RATELIMIT_ACTION.RESET_EPOCH:
                await r.areset(request)
        if no_execute and not default_action:
            return 0
        if iprestrict_action == RULE_ACTION.deny:
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
    @apply_iprestrict.register(list)
    @apply_iprestrict.register(tuple)
    def _(arg="", *args):
        args = list(args)
        if isinstance(arg, str):
            args.extend(arg.split(","))
        default_action = None
        for arg in args:
            if isinstance(arg, str):
                if arg.startswith("default_action:"):
                    default_action = arg.split(":", 1)[-1]
            elif isinstance(arg, (tuple, list)) and len(arg) >= 2:
                if arg[0] == "default_action":
                    # call to verify if already the right value/format
                    default_action = arg[1]
        return partial(
            apply_iprestrict.dispatch(HttpRequest),
            ignore_pathes="ignore_pathes" in args,
            require_rule="require_rule" in args,
            no_count="no_count" in args or "execute_only" in args,
            no_execute="no_execute" in args or "count_only" in args,
            default_action=default_action,
        )

else:

    def apply_iprestrict(*args, **kwargs):
        raise ImportError("ratelimit not installed")
