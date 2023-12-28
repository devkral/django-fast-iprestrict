from asgiref.sync import iscoroutinefunction, sync_to_async
from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.utils.decorators import sync_and_async_middleware

from .utils import get_ip


@sync_and_async_middleware
def fast_iprestrict(get_response):
    from .models import RulePath

    # One-time configuration and initialization goes here.
    if iscoroutinefunction(get_response):
        amatch_path_and_ip = sync_to_async(RulePath.objects.match_path_and_ip)

        async def middleware(request):
            action = await amatch_path_and_ip(
                request.path, get_ip(request), return_action=True
            )
            if not action:
                action = getattr(settings, "IPRESTRICT_DEFAULT_ACTION", "a")
            if action == "b":
                raise PermissionDenied()
            response = await get_response(request)
            return response

    else:

        def middleware(request):
            action = RulePath.objects.match_path_and_i(
                request.path, get_ip(request), return_action=True
            )
            if not action:
                action = getattr(settings, "IPRESTRICT_DEFAULT_ACTION", "a")
            if action == "b":
                raise PermissionDenied()
            response = get_response(request)
            return response

    return middleware
