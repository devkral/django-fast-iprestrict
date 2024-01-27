from posixpath import dirname

from django.conf import settings
from django.contrib import admin
from django.core.cache import caches
from django.core.exceptions import PermissionDenied
from django.db import models
from django.http import (
    HttpRequest,
    HttpResponse,
    HttpResponseBadRequest,
    HttpResponseRedirect,
)
from django.template.response import TemplateResponse
from django.urls import path
from django.utils.html import format_html

from .forms import LinkBackForm, TestRulesForm
from .models import (
    Rule,
    RuleNetwork,
    RulePath,
    RuleRatelimit,
    RuleRatelimitGroup,
    RuleSource,
)
from .utils import RULE_ACTION, LockoutException, get_ip, parse_ipaddress

try:
    import django_fast_ratelimit as ratelimit
except ImportError:
    ratelimit = None


class TestRulesMixin:
    def changelist_view(self, request, extra_context=None):
        default = {
            "test_rules_form": TestRulesForm(
                data={
                    **request.session.get("iprestrict_test_rules_data", {}),
                    "test_rules_form-link_back": request.path,
                },
                prefix="test_rules_form",
            )
        }
        if extra_context:
            default.update(extra_context)
        return super().changelist_view(
            request,
            extra_context=default,
        )


class RuleSubMixin(TestRulesMixin):
    if hasattr(admin, "ShowFacets"):
        show_facets = admin.ShowFacets.ALWAYS
    list_filter = ("is_active",)
    search_fields = ("rule__name",)

    def get_urls(self):
        return [
            path("<str:object_id>/change/", self.redirect_change),
            *super().get_urls(),
        ]

    def redirect_change(self, request, object_id):
        rulep = RulePath.objects.get(id=object_id)
        return HttpResponseRedirect(f"../../../rule/{rulep.rule_id}/change/")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


class ExtraOnlyOnInitialMixin:
    extra = 1

    def get_extra(self, request, obj=None, **kwargs):
        return self.extra if not obj else 0


class RulePathInlineAdmin(ExtraOnlyOnInitialMixin, admin.StackedInline):
    model = RulePath


class RuleRatelimitInlineAdmin(ExtraOnlyOnInitialMixin, admin.StackedInline):
    model = RuleRatelimit


class RuleNetworkInlineAdmin(ExtraOnlyOnInitialMixin, admin.TabularInline):
    model = RuleNetwork


class RuleSourceInlineAdmin(ExtraOnlyOnInitialMixin, admin.TabularInline):
    model = RuleSource


class RuleRatelimitGroupInlineAdmin(ExtraOnlyOnInitialMixin, admin.TabularInline):
    model = RuleRatelimitGroup


# reuse the existing form to prevent form nesting
_position_template = """
<div style="display:flex; gap: 16px" >
    <button
        style="border-radius: 30%;"
        name="rule_move_direction"
        title="start"
        value="start"
        formaction="{object_id}/rule_move/"
    >
        &#x21C8;
    </button>
    <button
        style="border-radius: 30%;"
        name="rule_move_direction"
        title="up" value="up"
        formaction="{object_id}/rule_move/"
    >
        &#x2191;
    </button>
    <button
        style="border-radius: 30%;"
        name="rule_move_direction"
        title="down" value="down"
        formaction="{object_id}/rule_move/"
    >
        &#x2193;
    </button>
    <button
        style="border-radius: 30%;"
        name="rule_move_direction"
        title="end"
        value="end"
        formaction="{object_id}/rule_move/"
    >
        &#x21CA;
    </button>
</div>
"""


class IsRatelimitMatcherFilter(admin.EmptyFieldListFilter):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.title = "Is ratelimit matcher"

    def choices(self, changelist):
        # shows wrong amount, so disable
        add_facets = False
        # changelist.add_facets
        facet_counts = self.get_facet_queryset(changelist) if add_facets else None
        for lookup, title, count_field in (
            (None, "All", None),
            ("1", "Normal", "empty__c"),
            ("0", "Ratelimit matching active", "not_empty__c"),
        ):
            if add_facets:
                if count_field is not None:
                    count = facet_counts[count_field]
                    title = f"{title} ({count})"
            yield {
                "selected": self.lookup_val == lookup,
                "query_string": changelist.get_query_string(
                    {self.lookup_kwarg: lookup}
                ),
                "display": title,
            }


@admin.register(Rule)
class RuleAdmin(TestRulesMixin, admin.ModelAdmin):
    if hasattr(admin, "ShowFacets"):
        show_facets = admin.ShowFacets.ALWAYS
    list_display = (
        "position_short",
        "position_buttons",
        "action",
        "name",
        "methods",
        "invert_methods",
        "is_ratelimit_matcher",
    )
    list_display_links = ("position_short",)
    list_editable = ("name", "action", "methods", "invert_methods")
    ordering = ("position",)
    fields = ["name", "action", "methods", "invert_methods"]
    list_filter = (
        "action",
        ("ratelimit_groups", IsRatelimitMatcherFilter),
    )
    search_fields = ("name",)
    inlines = [
        RuleNetworkInlineAdmin,
        RuleSourceInlineAdmin,
        RulePathInlineAdmin,
        RuleRatelimitInlineAdmin,
        RuleRatelimitGroupInlineAdmin,
    ]

    def get_list_filter(self, request):
        ret = list(super().get_list_filter(request))
        if request.GET.get("ratelimit_groups__isempty") != "1":
            ret.append("ratelimit_groups__name")
        return ret

    def get_queryset(self, request):
        return (
            super()
            .get_queryset(request)
            .annotate(
                has_ratelimit_groups=models.Exists(
                    RuleRatelimitGroup.objects.filter(
                        is_active=True, rule_id=models.OuterRef("id")
                    )
                )
            )
        )

    def get_urls(self):
        return [
            path("test_rules/", self.test_rules),
            path("clear_caches/", self.clear_iprestrict_caches),
            path(
                "simulate_rules<path:test_path>",
                self.simulate_rules,
            ),
            path("<str:object_id>/rule_move/", self.rule_move),
            *super().get_urls(),
        ]

    def changeform_view(self, request, object_id=None, form_url="", extra_context=None):
        try:
            return super().changeform_view(
                request,
                object_id=object_id,
                form_url=form_url,
                extra_context=extra_context,
            )
        except LockoutException:
            context = {**self.admin_site.each_context(request), "link_back": "./"}
            return TemplateResponse(
                request,
                "admin/django_fast_iprestrict/lockout_prevented.html",
                context=context,
                status=400,
            )

    def changelist_view(self, request, extra_context=None):
        try:
            return super().changelist_view(
                request,
                extra_context=extra_context,
            )
        except LockoutException:
            context = {**self.admin_site.each_context(request), "link_back": "./"}
            return TemplateResponse(
                request,
                "admin/django_fast_iprestrict/lockout_prevented.html",
                context=context,
                status=400,
            )

    def save_model(self, request, obj, form, change):
        obj._trigger_cleanup = False
        super().save_model(request, obj, form, change)

    def delete_model(self, request, obj):
        obj._trigger_cleanup = False
        super().delete_model(request, obj)
        Rule.objects.position_cleanup(ip=get_ip(request), path=request.path)

    def delete_queryset(self, request, queryset):
        super().delete_queryset(request, queryset)
        parent_path = dirname(request.path.rstrip("/"))

        Rule.objects.position_cleanup(ip=get_ip(request), path=parent_path)

    def save_related(self, request, form, formsets, change):
        super().save_related(request, form, formsets, change)
        Rule.objects.position_cleanup(ip=get_ip(request), path=request.path)

    def rule_move(self, request: HttpRequest, object_id):
        if request.method != "POST":
            # fail soft for browsers visiting this url
            return HttpResponseRedirect("../../")
        direction = request.POST["rule_move_direction"]
        parent_path = dirname(request.path.rstrip("/"))
        try:
            if direction == "up":
                self.model.objects.position_up(
                    object_id, ip=get_ip(request), path=parent_path
                )
            elif direction == "down":
                self.model.objects.position_down(
                    object_id, ip=get_ip(request), path=parent_path
                )
            elif direction == "start":
                self.model.objects.position_start(
                    object_id, ip=get_ip(request), path=parent_path
                )
            elif direction == "end":
                self.model.objects.position_end(
                    object_id, ip=get_ip(request), path=parent_path
                )
            else:
                return HttpResponseBadRequest()
        except LockoutException:
            context = {**self.admin_site.each_context(request), "link_back": "../../"}
            return TemplateResponse(
                request,
                "admin/django_fast_iprestrict/lockout_prevented.html",
                context=context,
                status=400,
            )
        return HttpResponseRedirect("../../")

    def simulate_rules(self, request, test_path):
        rule_id, action, is_catch_all, ratelimits = RulePath.objects.match_ip_and_path(
            get_ip(request), test_path
        )

        if ratelimit:
            for rdict in ratelimits:
                r = ratelimit.get_ratelimit(
                    request=request,
                    # don't use action
                    action=ratelimit.Action.PEEK,
                    group=rdict["group"],
                    key=rdict["key"],
                    rate=rdict["rate"],
                )
                r.decorate_object(
                    request, name=rdict["decorate_name"], block=rdict["block"]
                )
        if action == RULE_ACTION.deny:
            raise PermissionDenied()

        return HttpResponse(f"accessed: {test_path}")

    def test_rules(self, request):
        from django.contrib.messages import ERROR, INFO, SUCCESS, WARNING

        if request.method != "POST":
            # fail soft for browsers visiting this url
            return HttpResponseRedirect("../")
        form = TestRulesForm(
            request.POST,
            prefix="test_rules_form",
        )
        if form.is_valid():
            test_method = request.POST.get("test_method", None) or None
            test_ratelimit_group = (
                form.cleaned_data.get("test_ratelimit_group", None) or None
            )

            test_ip = form.cleaned_data.get("test_ip", None)
            if not test_ip:
                test_ip = get_ip(request)

            test_path = form.cleaned_data.get("test_path", None) or ""
            if test_path:
                rule_id = RulePath.objects.match_ip_and_path(
                    ip=test_ip,
                    path=test_path,
                    method=test_method,
                    ratelimit_group=test_ratelimit_group,
                )[0]
                self.message_user(
                    request,
                    f"Parameters: ip: {parse_ipaddress(test_ip)}, path: {test_path}, method: {test_method or '-'}, ratelimit group: {test_ratelimit_group or '-'}",
                    level=INFO,
                )
            else:
                rule_id = Rule.objects.match_ip(
                    ip=test_ip,
                    method=test_method,
                    ratelimit_group=test_ratelimit_group,
                )[0]
                self.message_user(
                    request,
                    f"Parameters: ip: {parse_ipaddress(test_ip)}, method: {test_method or '-'}",
                    level=INFO,
                )
            if rule_id:
                rule = Rule.objects.get(id=rule_id)
                self.message_user(
                    request,
                    f"Matched rule: {rule.name}, action: {RULE_ACTION(rule.action).label}",
                    level=SUCCESS
                    if rule.action == RULE_ACTION.allow.value
                    else WARNING,
                )
            else:
                self.message_user(request, "No rule matched", level=ERROR)

        session_data = {}

        for key in form.fields:
            prefixed_key = f"test_rules_form-{key}"
            if key != "link_back" and prefixed_key in form.data:
                session_data[prefixed_key] = form.data[prefixed_key]
        request.session["iprestrict_test_rules_data"] = session_data
        return HttpResponseRedirect(form.cleaned_data.get("link_back", "../"))

    def clear_iprestrict_caches(self, request):
        if request.method != "POST":
            # fail soft for browsers visiting this url
            raise HttpResponseRedirect("../")
        form = LinkBackForm(
            request.POST,
            prefix="test_rules_form",
        )
        if form.is_valid():
            # set => deduplicating
            for cache_name in {
                getattr(settings, "IPRESTRICT_CACHE", "default"),
                getattr(settings, "RATELIMIT_CACHE", "default"),
            }:
                caches[cache_name].clear()
        return HttpResponseRedirect(f"{form.cleaned_data.get('link_back', '../')}")

    @admin.display(description="")
    def position_short(self, obj):
        return obj.position

    @admin.display(ordering="position", description="Position")
    def position_buttons(self, obj):
        return format_html(
            _position_template,
            object_id=obj.id,
        )

    @admin.display(
        ordering="has_ratelimit_groups",
        description="is ratelimit matcher",
        boolean=True,
    )
    def is_ratelimit_matcher(self, obj):
        return obj.has_ratelimit_groups


@admin.register(RulePath)
class RulePathAdmin(RuleSubMixin, admin.ModelAdmin):
    list_display = ("rule", "path", "is_regex", "is_active")
    ordering = ("rule", "id")


@admin.register(RuleNetwork)
class RuleNetworkAdmin(RuleSubMixin, admin.ModelAdmin):
    list_display = ("rule", "network", "is_active")
    ordering = ("rule", "id")


@admin.register(RuleRatelimitGroup)
class RuleRatelimitGroupAdmin(RuleSubMixin, admin.ModelAdmin):
    list_display = ("rule", "name", "is_active")
    ordering = ("rule", "name")


@admin.register(RuleSource)
class RuleSourceAdmin(RuleSubMixin, admin.ModelAdmin):
    list_display = ("rule", "generator_fn", "is_active")
    ordering = ("rule", "id")
