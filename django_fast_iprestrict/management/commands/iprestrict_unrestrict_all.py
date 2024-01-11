from django.core.cache import caches
from django.core.management.base import BaseCommand

from ...models import Rule
from ...utils import RULE_ACTION


class Command(BaseCommand):
    help = "Emergency disable all rules and clear caches for reallowing login"

    def handle(self, **kwargs):
        Rule.objects.filter(action=RULE_ACTION.deny.value).update(
            action=RULE_ACTION.disabled.value
        )
        for cache in caches.all():
            cache.clear()
            cache.close()

        # clearing local_caches doesn't help, use different proccess
