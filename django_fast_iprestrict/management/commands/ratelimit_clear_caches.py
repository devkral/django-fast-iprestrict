from django.conf import settings
from django.core.cache import caches
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Clear caches"

    def add_arguments(self, parser):
        group = parser.add_mutually_exclusive_group()
        group.add_argument(
            "-n",
            "--names",
            nargs="+",
            default=(
                getattr(settings, "IPRESTRICT_CACHE", "default"),
                getattr(settings, "RATELIMIT_CACHE", "default"),
            ),
        )
        group.add_argument("--all", action="store_true", dest="clear_all")

    def handle(self, clear_all, names, **kwargs):
        for cache_name in set(caches if clear_all else names):
            print("clear", cache_name)
            cache = caches[cache_name]
            cache.clear()
        caches.close_all()
