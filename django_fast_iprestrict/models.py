import ipaddress
import re
from contextlib import ExitStack
from functools import lru_cache

from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Max, Window
from django.db.models.functions import RowNumber
from django.db.transaction import atomic

from .utils import RULE_ACTION, LockoutException, get_default_action
from .validators import validate_regex, validate_rule

# Create your models here.


def get_default_position():
    return Rule.objects.aggregate(Max("position", default=0))["position__max"] + 1


class RuleManager(models.Manager):
    def _atomic_update(self, ip=None, path=None, use_atomic=True):
        stack = ExitStack()
        stack.queryset = self.all().select_for_update()
        stack.enter_context(atomic())
        if ip:
            stack.callback(
                self.lockout_check, ip=ip, path=path, clear_caches_on_error=True
            )

        stack.callback(self._position_cleanup, stack.queryset)
        return stack

    def clear_caches(self):
        RulePath.objects.path_ip_matchers.cache_clear()
        self.ip_matchers.cache_clear()

    def lockout_check(self, ip, path=None, clear_caches_on_error=True):
        if not ip:
            return
        if path:
            if (
                get_default_action(
                    RulePath.objects.match_ip_and_path(ip, path, return_action=True)
                )
                == RULE_ACTION.deny.value
            ):
                # otherwise the caches could cause access errors until server restart
                if clear_caches_on_error:
                    self.clear_caches()
                raise LockoutException("would lock current user out")

        else:
            if (
                get_default_action(self.match_ip(ip, return_action=True))
                == RULE_ACTION.deny.value
            ):
                # otherwise the caches could cause access errors until server restart
                if clear_caches_on_error:
                    self.clear_caches()
                raise LockoutException("would lock current user out")

    def _position_cleanup(self, queryset):
        u_dict = {}
        # window functions don't like select_for_update
        for val in self.all().annotate(
            position_new=Window(expression=RowNumber(), order_by="position"),
        ):
            if val.position != val.position_new:
                u_dict[val.id] = val.position_new
        for rule_id, position in u_dict.items():
            queryset.filter(id=rule_id).update(position=position)
        self.clear_caches()

    def position_cleanup(self, ip=None, path=None):
        with self._atomic_update(ip=ip, path=path):
            pass

    @lru_cache(maxsize=1)
    def ip_matchers(self):
        patterns = []
        for obj in self.exclude(action=RULE_ACTION.disabled.value):
            patterns.append((obj.get_processed_rule(), obj.id, obj.action))
        return patterns

    def match_ip(self, ip, return_action=False):
        ip_network_user = ipaddress.ip_network(ip, strict=False)
        for ip_network, rule_id, action in self.ip_matchers():
            try:
                if ip_network == "*" or ip_network_user.subnet_of(ip_network):
                    return action if return_action else rule_id
            except TypeError:
                pass
        return None

    def position_start(self, rule_id, ip=None, path=None):
        with self._atomic_update(ip=ip, path=path) as stack:
            stack.queryset.filter(id=rule_id).update(position=0)

    def position_end(self, rule_id, ip=None, path=None):
        with self._atomic_update(ip=ip, path=path) as stack:
            max_position = stack.queryset.aggregate(
                max_position=Max("position", default=0)
            )["max_position"]
            # ugly hack
            self.get_queryset().annotate().filter(id=rule_id).update(
                position=max_position + 1
            )

    def position_up(self, rule_id, ip=None, path=None):
        with self._atomic_update(ip=ip, path=path) as stack:
            rule_position = stack.queryset.filter(id=rule_id).values("position")
            stack.queryset.annotate(
                position_mod=models.Case(
                    models.When(position__lte=1, id=rule_id, then=models.Value(0)),
                    models.When(id=rule_id, then=models.Value(-1)),
                    models.When(
                        position=models.Subquery(rule_position) - models.Value(1),
                        then=models.Value(1),
                    ),
                    default=models.Value(0),
                ),
            ).update(position=models.F("position") + models.F("position_mod"))

    def position_down(self, rule_id, ip=None, path=None):
        with self._atomic_update(ip=ip, path=path) as stack:
            rule_position = stack.queryset.filter(id=rule_id).values("position")
            stack.queryset.annotate(
                position_mod=models.Case(
                    models.When(id=rule_id, then=models.Value(1)),
                    models.When(
                        position=models.Subquery(rule_position) + models.Value(1),
                        then=models.Value(-1),
                    ),
                    default=models.Value(0),
                ),
            ).update(position=models.F("position") + models.F("position_mod"))


class Rule(models.Model):
    _trigger_cleanup = True
    position = models.PositiveIntegerField(blank=True, default=get_default_position)
    name = models.CharField(max_length=50, unique=True)
    rule = models.CharField(max_length=50, validators=[validate_rule])
    action = models.CharField(
        max_length=1, choices=RULE_ACTION.choices, default=RULE_ACTION.allow
    )
    objects = RuleManager()

    class Meta:
        ordering = ("position",)

        indexes = [
            models.Index(fields=["position"]),
        ]

    def __str__(self):
        return self.name

    def get_processed_rule(self):
        return (
            ipaddress.ip_network(self.rule, strict=False) if self.rule != "*" else "*"
        )

    def match_ip(self, ip, return_action=False):
        if self.action == RULE_ACTION.disabled.value:
            return None
        ip_network_user = ipaddress.ip_network(ip, strict=False)
        ip_network = self.get_processed_rule()
        try:
            if ip_network == "*" or ip_network_user.subnet_of(ip_network):
                return self.action if return_action else self.id
        except TypeError:
            pass
        return None


class RulePathManager(models.Manager):
    @lru_cache(maxsize=1)
    def path_ip_matchers(self):
        patterns = []
        last_pattern = None
        for obj in self.exclude(rule__action=RULE_ACTION.disabled.value).select_related(
            "rule"
        ):
            if not last_pattern or last_pattern[1] != obj.id:
                if last_pattern:
                    patterns.append((re.compile(last_pattern[0]), *last_pattern[1:]))
                last_pattern = [
                    obj.get_processed_path(),
                    obj.rule.get_processed_rule(),
                    obj.rule_id,
                    obj.rule.action,
                ]
            else:
                last_pattern[0] = "%s|%s" % (
                    last_pattern[0],
                    obj.get_processed_path(),
                )
        if last_pattern:
            patterns.append((re.compile(last_pattern[0]), *last_pattern[1:]))
        return patterns

    def match_ip_and_path(self, ip, path, return_action=False):
        ip_network_user = ipaddress.ip_network(ip, strict=False)
        for path_pattern, ip_network, rule_id, action in self.path_ip_matchers():
            try:
                if path_pattern.match(path) and (
                    ip_network == "*" or ip_network_user.subnet_of(ip_network)
                ):
                    return action if return_action else rule_id
            except TypeError:
                pass
        return None


class RulePath(models.Model):
    rule = models.ForeignKey(Rule, related_name="urls", on_delete=models.CASCADE)
    path = models.TextField(max_length=4096)
    is_regex = models.BooleanField(default=False, blank=True)
    objects = RulePathManager()

    class Meta:
        ordering = ("rule__position", "id")

    def __str__(self):
        return self.path

    def get_processed_path(self):
        return self.path if self.is_regex else re.escape(self.path)

    def clean_fields(self, exclude=None):
        super().clean_fields(exclude=exclude)
        if self.is_regex:
            try:
                validate_regex(self.path)
            except ValidationError as exc:
                if exclude and "path" in exclude:
                    raise exc
                else:
                    raise ValidationError({"path": exc})
