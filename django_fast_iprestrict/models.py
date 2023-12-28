import ipaddress
import re
from contextlib import ExitStack
from functools import lru_cache

from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Max, Window
from django.db.models.functions import RowNumber
from django.db.transaction import atomic

from .validators import validate_regex, validate_rule

# Create your models here.


def get_default_position():
    return Rule.objects.aggregate(Max("position", default=0))["position__max"] + 1


class RuleManager(models.Manager):
    def _atomic_update(self):
        stack = ExitStack()
        stack.queryset = self.all().select_for_update()
        stack.enter_context(atomic())
        return stack

    def _position_cleanup(self, queryset):
        u_dict = {}
        for val in queryset.annotate(
            position_new=Window(expression=RowNumber(), order_by="position"),
        ):
            if val.position != val.position_new:
                u_dict[val.id] = val.position_new
        for rule_id, position in u_dict.items():
            queryset.filter(id=rule_id).update(position=position)
        RulePath.objects.path_ip_matchers.cache_clear()
        self.ip_matchers.cache_clear()

    def position_cleanup(self):
        with self._atomic_update() as stack:
            self._position_cleanup(stack.queryset)

    @lru_cache(maxsize=1)
    def ip_matchers(self):
        patterns = []
        for obj in self.exclude(action="c"):
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

    def position_start(self, rule_id):
        with self._atomic_update() as stack:
            stack.queryset.filter(id=rule_id).update(position=0)
            self._position_cleanup(stack.queryset)

    def position_end(self, rule_id):
        with self._atomic_update() as stack:
            max_position = stack.queryset.aggregate(
                max_position=Max("position", default=0)
            )["max_position"]
            # ugly hack
            self.get_queryset().annotate().filter(id=rule_id).update(
                position=max_position + 1
            )
            self._position_cleanup(stack.queryset)

    def position_up(self, rule_id):
        with self._atomic_update() as stack:
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
            self._position_cleanup(stack.queryset)

    def position_down(self, rule_id):
        with self._atomic_update() as stack:
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
            self._position_cleanup(stack.queryset)


class Rule(models.Model):
    position = models.PositiveIntegerField(blank=True, default=get_default_position)
    name = models.CharField(max_length=50, unique=True)
    rule = models.CharField(max_length=50, validators=[validate_rule])
    ACTION = {"a": "allow", "b": "deny", "c": "disabled"}
    action = models.CharField(max_length=1, choices=ACTION, default="a")
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
        if self.action == "c":
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
        for obj in self.exclude(rule__action="c").select_related("rule"):
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

    def match_path_and_ip(self, path, ip, return_action=False):
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
