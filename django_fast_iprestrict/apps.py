from django.apps import AppConfig
from django.db.models.signals import post_delete


def signal_position_cleanup(**kwargs):
    from .models import Rule

    Rule.objects.position_cleanup()


class DjangoFastIprestrictConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "django_fast_iprestrict"

    def ready(self):
        from .models import Rule

        post_delete.connect(
            signal_position_cleanup,
            sender=Rule,
            dispatch_uid="django-fast-iprestrict-after-deletion",
        )
