from asgiref.sync import iscoroutinefunction, sync_to_async
from django.core.exceptions import PermissionDenied
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
        amatch_ip_and_path = sync_to_async(RulePath.objects.match_ip_and_path)

        async def middleware(request):
            action, _, ratelimits = (
                await amatch_ip_and_path(get_ip(request), request.path)
            )[1:]
            if ratelimit:
                for rdict in ratelimits:
                    r = await ratelimit.aget_ratelimit(
                        request=request,
                        action=ratelimit.Action.INCREASE,
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
            response = await get_response(request)
            return response

    else:

        def middleware(request):
            action, _, ratelimits = RulePath.objects.match_ip_and_path(
                get_ip(request), request.path
            )[1:]

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
                raise PermissionDenied()
            response = get_response(request)
            return response

    return middleware
