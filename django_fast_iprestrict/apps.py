from django.apps import AppConfig
from django.db.models.signals import post_delete, post_save


def signal_position_cleanup(instance, raw=False, **kwargs):
    from .models import Rule

    if raw:
        return
    if not instance._trigger_cleanup:
        return

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

        post_save.connect(
            signal_position_cleanup,
            sender=Rule,
            dispatch_uid="django-fast-iprestrict-after-save",
        )
