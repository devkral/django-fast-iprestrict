from django.apps import AppConfig
from django.db.models.signals import post_delete, post_save


def signal_position_cleanup(instance, raw=False, **kwargs):
    from .models import Rule

    if raw:
        return
    if not instance._trigger_cleanup:
        return

    Rule.objects.position_cleanup()


def clear_local_caches(instance, raw=False, **kwargs):
    from .models import Rule

    if raw:
        return

    Rule.objects.clear_local_caches()


class DjangoFastIprestrictConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "django_fast_iprestrict"

    def ready(self):
        from .models import Rule, RuleNetwork, RulePath, RuleRatelimitGroup

        post_delete.connect(
            signal_position_cleanup,
            sender=Rule,
            dispatch_uid="django-fast-iprestrict-after-deletion-rule",
        )

        post_save.connect(
            signal_position_cleanup,
            sender=Rule,
            dispatch_uid="django-fast-iprestrict-after-save-rule",
        )
        post_save.connect(
            clear_local_caches,
            sender=RuleNetwork,
            dispatch_uid="django-fast-iprestrict-after-save-rule-network",
        )
        post_delete.connect(
            clear_local_caches,
            sender=RuleNetwork,
            dispatch_uid="django-fast-iprestrict-after-deletion-rule-network",
        )

        post_save.connect(
            clear_local_caches,
            sender=RulePath,
            dispatch_uid="django-fast-iprestrict-after-save-rule-path",
        )
        post_delete.connect(
            clear_local_caches,
            sender=RulePath,
            dispatch_uid="django-fast-iprestrict-after-deletion-rule-path",
        )

        post_save.connect(
            clear_local_caches,
            sender=RuleRatelimitGroup,
            dispatch_uid="django-fast-iprestrict-after-save-rule-ratelimit-group",
        )
        post_delete.connect(
            clear_local_caches,
            sender=RuleRatelimitGroup,
            dispatch_uid="django-fast-iprestrict-after-deletion-rule-ratelimit-group",
        )
