import re
from contextlib import ExitStack
from functools import lru_cache

from django.conf import settings
from django.core.cache import caches
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Max, Window
from django.db.models.functions import Concat, RowNumber
from django.db.transaction import atomic
from django.utils.module_loading import import_string

from .utils import (
    RULE_ACTION,
    LockoutException,
    get_default_action,
    get_default_interval,
    parse_ipaddress,
    parse_ipnetwork,
)
from .validators import validate_generator_fn, validate_network, validate_regex

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

    def clear_local_caches(self):
        RulePath.objects.path_ip_matchers.cache_clear()
        self.ip_matchers_local.cache_clear()

    def lockout_check(self, ip, path=None, clear_caches_on_error=True):
        if not ip:
            return
        if path:
            if (
                get_default_action(
                    RulePath.objects.match_ip_and_path(ip, path, remote=False)[1]
                )
                == RULE_ACTION.deny.value
            ):
                # otherwise the caches could cause access errors until server restart
                if clear_caches_on_error:
                    self.clear_local_caches()
                raise LockoutException("would lock current user out")

        else:
            if (
                get_default_action(self.match_ip(ip, remote=False)[1])
                == RULE_ACTION.deny.value
            ):
                # otherwise the caches could cause access errors until server restart
                if clear_caches_on_error:
                    self.clear_local_caches()
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
        self.clear_local_caches()

    def position_cleanup(self, ip=None, path=None):
        with self._atomic_update(ip=ip, path=path):
            pass

    @lru_cache(maxsize=1)
    def ip_matchers_local(self):
        # ordered dict
        patterns = {}
        for obj in self.exclude(action=RULE_ACTION.disabled.value):
            patterns[obj.id] = (obj.get_processed_networks(), obj.action)
        return patterns

    def match_ip(self, ip: str, rule_id=None, remote=True):
        ip_address_user = parse_ipaddress(ip)
        if rule_id:
            item = self.ip_matchers_local()[rule_id]
            for network in item[0]:
                try:
                    if network == "*" or ip_address_user in network:
                        return rule_id, item[1]
                except TypeError:
                    pass
            if remote:
                for network in RuleSource.objects.ip_matchers_remote(rule_id):
                    try:
                        if ip_address_user in network:
                            return rule_id, item[1]
                    except TypeError:
                        pass

        else:
            ip_matchers = self.ip_matchers_local()
            for rule_id, item in ip_matchers.items():
                for network in item[0]:
                    try:
                        if network == "*" or ip_address_user in network:
                            return rule_id, item[1]
                    except TypeError:
                        pass
            if remote:
                for network in RuleSource.objects.ip_matchers_remote(
                    ip_matchers.keys()
                ):
                    try:
                        if ip_address_user in network:
                            return rule_id, item[1]
                    except TypeError:
                        pass

        return None, None

    def match_all_ip(self, ip: str, remote=True):
        ip_address_user = parse_ipaddress(ip)
        result = []
        ip_matchers = self.ip_matchers_local()
        for rule_id, item in ip_matchers.items():
            for network in item[0]:
                try:
                    if network == "*" or ip_address_user in network:
                        result.append((rule_id, item[1]))
                except TypeError:
                    pass
        if remote:
            for network in RuleSource.objects.ip_matchers_remote(ip_matchers.keys()):
                try:
                    if ip_address_user in network:
                        result.append((rule_id, item[1]))
                except TypeError:
                    pass

        return result

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

    @property
    def is_catch_all(self):
        return (
            not self.sources.filter(is_active=True).exists()
            and not self.networks.filter(is_active=True).exists()
        )

    def get_processed_networks(self):
        if self.is_catch_all:
            return ["*"]
        return [
            parse_ipnetwork(network)
            for network in self.networks.filter(is_active=True).values_list(
                "network", flat=True
            )
        ]

    def match_ip(self, ip):
        return type(self).objects.match_ip(ip, rule_id=self.id)


class RuleNetwork(models.Model):
    rule = models.ForeignKey(Rule, related_name="networks", on_delete=models.CASCADE)
    network = models.CharField(max_length=50, validators=[validate_network])
    is_active = models.BooleanField(blank=True, default=True)


class RuleSourceManager(models.Manager):
    def clear_remote_caches(self):
        cache = caches[getattr(settings, "IPRESTRICT_CACHE", "default")]
        cache.delete_many(
            self.annotate_with_cache_key().values_list("cache_key", flat=True)
        )

    def annotate_with_cache_key(self, queryset=None):
        if queryset is None:
            queryset = self.get_queryset()
        return queryset.annotate(
            cache_key=Concat(
                models.Value(
                    f'{getattr(settings, "IPRESTRICT_KEY_PREFIX", "fip:")}source_data'
                ),
                models.F("id"),
                output_field=models.TextField(),
            )
        )

    def ip_matchers_remote(self, rules):
        cache = caches[getattr(settings, "IPRESTRICT_CACHE", "default")]
        q = models.Q(is_active=True)
        if isinstance(rules, models.QuerySet):
            q &= models.Q(rule__in=rules)
        else:
            q &= models.Q(rule_id__in=rules)
        keys_query = self.annotate_with_cache_key(self.filter(q))
        keys = keys_query.values_list("cache_key", flat=True)

        # unordered dict
        result = cache.get_many(keys)
        for source in keys_query.exclude(id__in=result.keys()):
            # FIXME: double calling, some kind of locking would be good
            networks = source.get_processed_networks_uncached()
            cache_key = source.get_cache_key()
            result[cache_key] = networks
            cache.set(
                cache_key,
                ",".join(map(lambda x: x.compressed, networks)),
                source.interval,
            )

        for key in result.keys():
            value = result[key]
            if isinstance(value, str):
                result[key] = [parse_ipnetwork(network) for network in value.split(",")]

        return result


class RuleSource(models.Model):
    rule = models.ForeignKey(Rule, related_name="sources", on_delete=models.CASCADE)
    generator_fn = models.CharField(
        default="",
        max_length=200,
        null=False,
        blank=True,
        validators=[
            validate_generator_fn,
        ],
    )
    interval = models.PositiveIntegerField(blank=True, default=get_default_interval)
    is_active = models.BooleanField(blank=True, default=True)

    objects = RuleSourceManager()

    def get_cache_key(self):
        return (
            f'{getattr(settings, "IPRESTRICT_KEY_PREFIX", "fip:")}source_data{self.id}'
        )

    def get_processed_networks_uncached(self):
        ret = []
        success = False
        try:
            validate_generator_fn(self.generator_fn)
            success = True
        except ValidationError:
            pass
        if success:
            try:
                ip_nets = import_string(self.generator_fn)()
            except ImportError:
                # FIXME: proper reporting
                return
            except Exception:
                # FIXME: proper reporting
                return
            for network in ip_nets:
                try:
                    ret.append(parse_ipnetwork(network))
                except ValueError:
                    pass

        return ret


class RulePathManager(models.Manager):
    @lru_cache(maxsize=1)
    def path_matchers(self):
        patterns = {}
        for obj in self.exclude(rule__action=RULE_ACTION.disabled.value).filter(
            is_active=True
        ):
            patterns.setdefault(obj.rule_id, []).append(obj.get_processed_path())
        for key in patterns.keys():
            patterns[key] = re.compile("|".join(patterns[key]))
        return patterns

    def match_ip_and_path(self, ip: str, path: str, remote=True):
        # ordered
        candidates = Rule.objects.match_all_ip(ip, remote=remote)
        _path_matchers = self.path_matchers()
        for rule_id, action in candidates:
            matcher = _path_matchers.get(rule_id)
            if matcher and matcher.match(path):
                return rule_id, action
        return None, None


class RulePath(models.Model):
    rule = models.ForeignKey(Rule, related_name="pathes", on_delete=models.CASCADE)
    path = models.TextField(max_length=4096)
    is_regex = models.BooleanField(default=False, blank=True)
    is_active = models.BooleanField(blank=True, default=True)

    objects = RulePathManager()

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
                if exclude and "path" in exclude:
                    raise exc
                else:
                    raise ValidationError({"path": exc})
                    raise ValidationError({"path": exc})
