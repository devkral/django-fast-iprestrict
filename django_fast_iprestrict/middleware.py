from asgiref.sync import iscoroutinefunction, sync_to_async
from django.core.exceptions import PermissionDenied
from django.utils.decorators import sync_and_async_middleware

from .utils import RULE_ACTION, get_default_action, get_ip


@sync_and_async_middleware
def fast_iprestrict(get_response):
    from .models import RulePath

    # One-time configuration and initialization goes here.
    if iscoroutinefunction(get_response):
        amatch_ip_and_path = sync_to_async(RulePath.objects.match_ip_and_path)

        async def middleware(request):
            action = get_default_action(
                (await amatch_ip_and_path(get_ip(request), request.path))[1]
            )
            if action == RULE_ACTION.deny.value:
                raise PermissionDenied()
            response = await get_response(request)
            return response

    else:

        def middleware(request):
            action = get_default_action(
                RulePath.objects.match_ip_and_path(get_ip(request), request.path)[1]
            )
            if action == RULE_ACTION.deny.value:
                raise PermissionDenied()
            response = get_response(request)
            return response

    return middleware
