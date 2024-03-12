import logging
import re
import time
from contextlib import ExitStack
from functools import lru_cache
from typing import Optional

from asgiref.sync import sync_to_async
from django.conf import settings
from django.core.cache import caches
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Max, Window
from django.db.models.functions import Concat, RowNumber
from django.db.transaction import atomic
from django.utils.module_loading import import_string

from .utils import (
    RATELIMIT_ACTION,
    RULE_ACTION,
    LockoutException,
    get_default_action,
    get_default_interval,
    invertedset,
    parse_ipaddress,
    parse_ipnetwork,
)
from .validators import (
    min_length_1,
    validate_generator_fn,
    validate_methods,
    validate_network,
    validate_path,
    validate_rate,
    validate_ratelimit_key,
    validate_regex,
)

logger = logging.getLogger(__name__)
# Create your models here.

_empty = ()
_update_interval_secs = 2 * 60


def get_default_position():
    return Rule.objects.aggregate(Max("position", default=0))["position__max"] + 1


class Manageable(models.Model):
    managed_fields = models.JSONField(blank=True, default=list, editable=False)

    class Meta:
        abstract = True

    def clean(self):
        super().clean()
        valid_names = {i.name for i in self._meta.get_fields()}
        valid_names.discard("position")
        self.managed_fields = list(valid_names.intersection(self.managed_fields))


class ActivatableAndManageable(Manageable):
    is_active = models.BooleanField(blank=True, default=True)

    class Meta:
        abstract = True


class RuleManager(models.Manager):
    _next_rules_updates = time.monotonic() + _update_interval_secs

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
        RulePath.objects.path_matchers.cache_clear()
        RuleRatelimitGroup.objects.name_matchers.cache_clear()
        self._ip_matchers_local.cache_clear()
        self._next_rules_updates = time.monotonic() + _update_interval_secs

    def lockout_check(self, ip, path=None, clear_caches_on_error=True, remote=False):
        if not ip:
            return
        if path:
            if (
                RulePath.objects.match_ip_and_path(ip=ip, path=path, remote=remote)[1]
                == RULE_ACTION.deny
            ):
                # otherwise the caches could cause access errors until server restart
                if clear_caches_on_error:
                    self.clear_local_caches()
                raise LockoutException("would lock current user out")

        else:
            if self.match_ip(ip=ip, remote=remote)[1] == RULE_ACTION.deny:
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

    @lru_cache(maxsize=2)
    def _ip_matchers_local(self, generic=False):
        # ordered dict
        patterns = {}
        name_matchers = RuleRatelimitGroup.objects.name_matchers()[0]
        queryset = self.annotate(
            has_networks=models.Exists(
                RuleNetwork.objects.filter(
                    is_active=True, rule_id=models.OuterRef("id")
                )
            ),
            has_sources=models.Exists(
                RuleSource.objects.filter(is_active=True, rule_id=models.OuterRef("id"))
            ),
            has_pathes=models.Exists(
                RulePath.objects.filter(is_active=True, rule_id=models.OuterRef("id"))
            ),
        )
        if not generic:
            # non catchalls are excluded, when without network/source
            queryset = queryset.exclude(
                models.Q(has_sources=False, has_networks=False, has_pathes=True)
            ).exclude(action=RULE_ACTION.disabled.value)
        for obj in queryset.distinct():
            patterns[obj.id] = (
                ["*"] if obj._is_catchall() else obj.get_processed_networks(),  # 0
                obj.get_methods(),  # 1
                name_matchers.get(
                    obj.id, _empty
                ),  # 2, note MUST be _empty otherwise the detection if a RuleRatelimitGroup is just disabled fails
                RULE_ACTION(obj.action),  # 3
                obj._is_catchall(),  # 4
                obj.get_ratelimit_dicts(),  # 5
            )
        return patterns

    def ip_matchers_local(self, generic=False):
        if self._next_rules_updates < time.monotonic():
            self.clear_local_caches()
        return self._ip_matchers_local(generic=generic)

    aip_matchers_local = sync_to_async(ip_matchers_local)

    def match_ip(
        self,
        ip: str,
        method: Optional[str] = None,
        ratelimit_group: Optional[str] = None,
        rule_id: Optional[int] = None,
        generic=False,
        remote=True,
        # overwrite default action
        default_action=None,
    ):
        ip_address_user = parse_ipaddress(ip)
        if rule_id:
            item = self.ip_matchers_local(generic=generic).get(rule_id, None)
            if not item:
                return None, get_default_action(default_action), False, _empty
            if method and method not in item[1]:
                return None, get_default_action(default_action), False, _empty

            if ratelimit_group:
                if ratelimit_group not in item[2]:
                    return None, get_default_action(default_action), False, _empty
            elif item[2] is not _empty:
                return None, get_default_action(default_action), False, _empty

            for network in item[0]:
                try:
                    if network == "*" or ip_address_user in network:
                        return rule_id, *item[3:]
                except TypeError:
                    pass
            if remote:
                for remote_networks in RuleSource.objects.ip_matchers_remote(
                    [rule_id]
                ).values():
                    # maximal one
                    for network in remote_networks:
                        try:
                            if ip_address_user in network:
                                return rule_id, *item[3:]
                        except TypeError:
                            pass

        else:
            ip_matchers = self.ip_matchers_local(generic=generic)
            ip_matchers_remote = (
                RuleSource.objects.ip_matchers_remote(ip_matchers.keys())
                if remote
                else {}
            )
            for rule_id, item in ip_matchers.items():
                if method and method not in item[1]:
                    continue
                if ratelimit_group:
                    if ratelimit_group not in item[2]:
                        continue
                elif item[2] is not _empty:
                    continue

                for network in item[0]:
                    try:
                        if network == "*" or ip_address_user in network:
                            return rule_id, *item[3:]
                    except TypeError:
                        pass

                for network in ip_matchers_remote.get(str(rule_id), _empty):
                    try:
                        if ip_address_user in network:
                            return rule_id, *item[3:]
                    except TypeError:
                        pass
        return None, get_default_action(default_action), False, _empty

    amatch_ip = sync_to_async(match_ip)

    def match_all_ip(
        self,
        ip: str,
        method: Optional[str] = None,
        ratelimit_group=None,
        remote=True,
        generic=False,
    ):
        # note: cannot apply ratelimit here
        ip_address_user = parse_ipaddress(ip)
        result = []
        ip_matchers = self.ip_matchers_local(generic=generic)
        ip_matchers_remote = None
        for rule_id, item in ip_matchers.items():
            if method and method not in item[1]:
                continue
            if ratelimit_group:
                if ratelimit_group not in item[2]:
                    continue
            elif item[2] is not _empty:
                continue
            found_local_network = False
            for network in item[0]:
                try:
                    if network == "*" or ip_address_user in network:
                        result.append((rule_id, *item[3:]))
                        found_local_network = True
                        break
                except TypeError:
                    pass
            if found_local_network:
                continue
            # lazy fetch
            if ip_matchers_remote is None:
                ip_matchers_remote = (
                    RuleSource.objects.ip_matchers_remote(ip_matchers.keys())
                    if remote
                    else {}
                )
            for network in ip_matchers_remote.get(str(rule_id), _empty):
                try:
                    if ip_address_user in network:
                        result.append((rule_id, *item[2:]))
                        break
                except TypeError:
                    pass

        return result

    amatch_all_ip = sync_to_async(match_all_ip)

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

    def get_by_natural_key(self, name):
        return self.get(name=name)


class Rule(Manageable):
    _trigger_cleanup = True
    position = models.PositiveIntegerField(blank=True, default=get_default_position)
    name = models.CharField(max_length=50, unique=True)
    methods = models.CharField(
        max_length=100,
        validators=[validate_methods],
        default="",
        blank=True,
        help_text="comma seperated http methods",
    )
    invert_methods = models.BooleanField(
        default=True,
        blank=True,
        help_text="exclude instead of include http methods. Set and leave methods empty to match all",
    )
    action = models.CharField(
        max_length=1, choices=RULE_ACTION.choices, default=RULE_ACTION.disabled
    )
    objects = RuleManager()

    class Meta:
        ordering = ("position",)

        indexes = [
            models.Index(fields=["position"]),
        ]

    def __str__(self):
        return self.name

    def is_catch_all(self, also_disabled=False):
        rule = type(self).objects.ip_matchers_local(generic=also_disabled).get(self.id)
        return bool(rule and rule[3])

    def _is_catchall(self):
        # use annotations
        return not self.has_networks and not self.has_sources

    def get_processed_networks(self):
        return [
            parse_ipnetwork(network)
            for network in self.networks.filter(is_active=True).values_list(
                "network", flat=True
            )
        ]

    def get_ratelimit_dicts(self):
        return list(
            self.ratelimits.filter(is_active=True).values(
                "key", "group", "rate", "decorate_name", "block", "wait", "action"
            )
        )

    def get_methods(self):
        if self.invert_methods:
            if not self.methods:
                return invertedset()
            return invertedset(self.methods.split(","))
        if not self.methods:
            return set()
        return set(self.methods.split(","))

    def match_ip(self, ip, method=None, remote=True, generic=False):
        return type(self).objects.match_ip(
            ip, method=method, rule_id=self.id, remote=remote, generic=generic
        )

    amatch_ip = sync_to_async(match_ip)

    def clean(self):
        super().clean()
        self.methods = ",".join(
            sorted(map(lambda x: x.upper().strip(), self.methods.split(",")))
        )

    def natural_key(self):
        return (self.name,)


class RuleRatelimitManager(models.Manager):
    pass


class RuleRatelimit(ActivatableAndManageable):
    rule = models.ForeignKey(Rule, related_name="ratelimits", on_delete=models.CASCADE)
    key = models.CharField(
        max_length=200,
        validators=[
            validate_ratelimit_key,
        ],
    )
    group = models.CharField(max_length=50)
    decorate_name = models.CharField(max_length=50, default="ratelimit", blank=True)
    action = models.SmallIntegerField(
        choices=RATELIMIT_ACTION.choices,
        default=RATELIMIT_ACTION.INCREASE,
    )
    rate = models.CharField(
        max_length=10,
        validators=[validate_rate],
        help_text=(
            'Set to "inherit" to use the provided rate (when set to "inherit" '
            "ratelimit is ignored in middleware and without a provided rate)"
        ),
    )
    block = models.BooleanField(blank=True, default=False)
    wait = models.BooleanField(blank=True, default=False)

    objects = RuleRatelimitManager()


class RuleRatelimitGroupManager(models.Manager):
    @lru_cache(maxsize=1)
    def name_matchers(self):
        rule_id_to_names = {}
        name_has_pathes = set()
        for obj in self.annotate(
            has_pathes=models.Exists(
                RulePath.objects.filter(
                    is_active=True, rule_id=models.OuterRef("rule_id")
                )
            )
        ):
            # we always annotate with a set, to differ from _empty
            set_ob = rule_id_to_names.setdefault(obj.rule_id, set())
            if obj.is_active:
                if obj.has_pathes:
                    name_has_pathes.add(obj.name)
                set_ob.add(obj.name)
        return rule_id_to_names, name_has_pathes

    aname_matchers = sync_to_async(name_matchers)


class RuleRatelimitGroup(ActivatableAndManageable):
    rule = models.ForeignKey(
        Rule, related_name="ratelimit_groups", on_delete=models.CASCADE
    )
    name = models.CharField(
        max_length=80,
        verbose_name="ratelimit group name",
        help_text="matcher for django-fast-ratelimit group",
        validators=[min_length_1],
    )

    objects = RuleRatelimitGroupManager()

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["rule", "name"], name="rule_ratelimit_groups_unique"
            )
        ]


class RuleNetwork(ActivatableAndManageable):
    rule = models.ForeignKey(Rule, related_name="networks", on_delete=models.CASCADE)
    network = models.CharField(max_length=50, validators=[validate_network])

    def __str__(self):
        return self.network


class RuleSourceManager(models.Manager):
    def clear_remote_caches(
        self,
    ):
        cache = caches[getattr(settings, "IPRESTRICT_CACHE", "default")]
        cache.delete_many(
            self.annotate_with_cache_key().values_list("cache_key", flat=True),
        )

    def annotate_with_cache_key(self, queryset=None):
        if queryset is None:
            queryset = self.get_queryset()
        # last is rule id for easy extraction
        return queryset.annotate(
            cache_key=Concat(
                models.Value(
                    f'{getattr(settings, "IPRESTRICT_KEY_PREFIX", "fip:")}source_data:'
                ),
                models.F("id"),
                models.Value(":"),
                models.F("rule_id"),
                output_field=models.TextField(),
            ),
            force_expire_cache_key=Concat(
                models.Value(
                    f'{getattr(settings, "IPRESTRICT_KEY_PREFIX", "fip:")}source_force_expire:'
                ),
                models.F("interval"),
                models.Value(":"),
                models.F("rule_id"),
                output_field=models.TextField(),
            ),
        )

    def _is_force_expired(self, query, cache, set_all):
        if set_all:
            return set(query.values_list("cache_key", flat=True))
        expire_dates = cache.get_many(
            set(query.values_list("force_expire_cache_key", flat=True))
        )
        cur_time = int(time.time())
        expired = set()
        for source in query:
            if (
                source.force_expire_cache_key not in expire_dates
                or expire_dates[source.force_expire_cache_key] < cur_time
            ):
                expired.add(source.cache_key)
        return expired

    def ip_matchers_remote(self, rules):
        cache = caches[getattr(settings, "IPRESTRICT_CACHE", "default")]
        q = models.Q(is_active=True)
        if isinstance(rules, models.QuerySet):
            q &= models.Q(rule__in=rules)
        else:
            q &= models.Q(rule_id__in=rules)
        keys_query = self.annotate_with_cache_key(self.filter(q))
        keys = keys_query.values_list("cache_key", flat=True)
        max_interval = keys_query.aggregate(Max("interval", default=0))["interval__max"]
        force_expire = bool(getattr(settings, "IPRESTRICT_SOURCE_FORCE_EXPIRE", True))
        # <= force_expire_multiplier <= 0 disables force expire
        skip_cache = (
            set()
            if not force_expire
            else self._is_force_expired(keys_query, cache, max_interval == 0)
        )
        cache_result = (
            cache.get_many(set(keys).difference(skip_cache))
            if max_interval > 0 and not skip_cache
            else {}
        )
        last_interval = None
        to_set = {}
        result = {}

        for source in (
            keys_query.exclude(cache_key__in=cache_result.keys())
            .distinct()
            .order_by("interval")
        ):
            # FIXME: double calling, some kind of locking would be good
            networks = source.get_processed_networks_uncached()
            # annotated
            cache_key = source.cache_key
            force_expire_cache_key = source.force_expire_cache_key
            result.setdefault(cache_key.rsplit(":", 1)[-1], []).extend(networks)
            if last_interval is not None and last_interval != source.interval:
                # not empty
                if to_set:
                    cache.set_many(to_set, timeout=last_interval)
                to_set = {}
            # interval 0 disables caching
            if source.interval > 0:
                to_set[cache_key] = ",".join(map(lambda x: x.compressed, networks))
                if force_expire:
                    to_set[force_expire_cache_key] = int(time.time()) + source.interval

            last_interval = source.interval
        if last_interval is not None:
            # not empty
            if to_set:
                cache.set_many(to_set, timeout=last_interval)

        for cache_key, value in cache_result.items():
            if isinstance(value, str):
                result_key = cache_key.rsplit(":", 1)[-1]
                networks = result.setdefault(result_key, [])
                for network_str in value.split(","):
                    try:
                        networks.append(parse_ipnetwork(network_str))
                    except ValueError:
                        pass
        return result

    def __str__(self):
        return self.generator_fn


class RuleSource(ActivatableAndManageable):
    rule = models.ForeignKey(Rule, related_name="sources", on_delete=models.CASCADE)
    generator_fn = models.CharField(
        max_length=200,
        validators=[
            validate_generator_fn,
        ],
    )
    interval = models.PositiveIntegerField(blank=True, default=get_default_interval)
    objects = RuleSourceManager()

    def get_cache_key(self):
        # last is rule id for easy extraction
        return f'{getattr(settings, "IPRESTRICT_KEY_PREFIX", "fip:")}source_data:{self.id}:{self.rule_id}'

    def get_force_expire_cache_key(self):
        return f'{getattr(settings, "IPRESTRICT_KEY_PREFIX", "fip:")}source_force_expire:{self.interval}:{self.rule_id}'

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
            except ImportError as exc:
                logger.warning(
                    'could not import source generator_fn: "%s", rule name %s, source id %s',
                    self.generator_fn,
                    self.rule.name,
                    self.id,
                    exc_info=exc,
                )
                return []
            except Exception as exc:
                logger.error(
                    'source generator_fn "%s" failed, rule name %s, source id %s',
                    self.generator_fn,
                    self.rule.name,
                    self.id,
                    exc_info=exc,
                )
                return []
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

    apath_matchers = sync_to_async(path_matchers)

    def match_ip_and_path(
        self,
        ip: str,
        path: str,
        method: Optional[str] = None,
        ratelimit_group: Optional[str] = None,
        rule_id=None,
        remote=True,
        # overwrite default action
        default_action=None,
    ):
        # ordered
        # with generic = pathless, non-catchall and disabled candidates are included
        if rule_id:
            candidate = Rule.objects.match_ip(
                ip,
                rule_id=rule_id,
                method=method,
                ratelimit_group=ratelimit_group,
                remote=remote,
                generic=True,
            )
            if candidate[0] is not None:
                candidates = [candidate]
        else:
            candidates = Rule.objects.match_all_ip(
                ip,
                method=method,
                ratelimit_group=ratelimit_group,
                remote=remote,
                generic=True,
            )
        _path_matchers = self.path_matchers()
        ratelimits = []
        for _rule_id, action, is_catch_all, _ratelimits in candidates:
            if action == RULE_ACTION.disabled:
                continue
            matcher = _path_matchers.get(_rule_id, None)
            # matcher is None, catchall for pathes (can be also a real catch all)
            if matcher and matcher.match(path):
                ratelimits.extend(_ratelimits)
                if action == RULE_ACTION.only_ratelimit:
                    continue
                return _rule_id, action, is_catch_all, ratelimits
        return None, get_default_action(default_action), False, ratelimits

    amatch_ip_and_path = sync_to_async(match_ip_and_path)


class RulePath(ActivatableAndManageable):
    rule = models.ForeignKey(Rule, related_name="pathes", on_delete=models.CASCADE)
    path = models.TextField(max_length=4096)
    is_regex = models.BooleanField(default=False, blank=True)

    objects = RulePathManager()

    class Meta:
        verbose_name_plural = "Rule Pathes"

    def __str__(self):
        return self.path

    def get_processed_path(self):
        return self.path if self.is_regex else re.escape(self.path)

    def clean_fields(self, exclude=None):
        super().clean_fields(exclude=exclude)
        try:
            validate_regex(self.path) if self.is_regex else validate_path(self.path)
        except ValidationError as exc:
            if exclude and "path" in exclude:
                raise exc
            else:
                raise ValidationError({"path": exc})
