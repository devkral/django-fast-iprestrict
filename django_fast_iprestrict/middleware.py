from asgiref.sync import iscoroutinefunction
from django.core.exceptions import PermissionDenied
from django.db.utils import OperationalError
from django.utils.decorators import sync_and_async_middleware

from .utils import RULE_ACTION, get_ip

try:
    import django_fast_ratelimit as ratelimit
except ImportError:
    ratelimit = None


@sync_and_async_middleware
def fast_iprestrict(get_response):
    from .models import RulePath

    # One-time configuration and initialization goes here.
    if iscoroutinefunction(get_response):

        async def middleware(request):
            try:
                action, _, ratelimits = (
                    await RulePath.objects.amatch_ip_and_path(
                        get_ip(request), request.path
                    )
                )[1:]
                if ratelimit:
                    for rdict in ratelimits:
                        if rdict["rate"] == "inherit":
                            continue
                        r = await ratelimit.aget_ratelimit(
                            request=request,
                            action=rdict["action"],
                            group=rdict["group"],
                            key=rdict["key"],
                            rate=rdict["rate"],
                        )
                        await r.adecorate_object(
                            request,
                            name=rdict["decorate_name"],
                            block=rdict["block"],
                            wait=rdict["wait"],
                        )
                if action == RULE_ACTION.deny.value:
                    raise PermissionDenied()
            except OperationalError as exc:
                assert exc.args[0].startswith("no such table:")
            return await get_response(request)

    else:

        def middleware(request):
            try:
                action, _, ratelimits = RulePath.objects.match_ip_and_path(
                    get_ip(request), request.path
                )[1:]

                if ratelimit:
                    for rdict in ratelimits:
                        if rdict["rate"] == "inherit":
                            continue
                        r = ratelimit.get_ratelimit(
                            request=request,
                            action=rdict["action"],
                            group=rdict["group"],
                            key=rdict["key"],
                            rate=rdict["rate"],
                        )
                        r.decorate_object(
                            request, name=rdict["decorate_name"], block=rdict["block"]
                        )
                if action == RULE_ACTION.deny.value:
                    raise PermissionDenied()
            except OperationalError as exc:
                assert exc.args[0].startswith("no such table:")
            return get_response(request)

    return middleware
