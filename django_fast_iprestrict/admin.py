from django.contrib import admin
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse, HttpResponseRedirect
from django.urls import path
from django.utils.html import format_html

from .models import Rule, RulePath
from .utils import RULE_ACTION, get_default_action, get_ip

# Register your models here.


class RulePathInlineAdmin(admin.TabularInline):
    model = RulePath
    extra = 1


_position_template = """
<div style="display:flex; gap: 8px">
    <a href="{object_id}/rule_start/" title="start">&#x21C8;</a>
    |
    <a href="{object_id}/rule_up/" title="up">&#x2191;</a>
    |
    <a href="{object_id}/rule_down/" title="down">&#x2193;</a>
    |
    <a href="{object_id}/rule_end/" title="end">&#x21CA;</a>
</div>
"""


@admin.register(Rule)
class RuleAdmin(admin.ModelAdmin):
    list_display = ("position_short", "position_buttons", "action", "name", "rule")
    list_display_links = ("position_short",)
    list_editable = ("name", "action", "rule")
    ordering = ("position",)
    fields = ["name", "action", "rule"]
    inlines = [RulePathInlineAdmin]

    @admin.display(description="")
    def position_short(self, obj):
        return obj.position

    @admin.display(ordering="position")
    def position_buttons(self, obj):
        return format_html(_position_template, object_id=obj.id)

    def get_changeform_initial_data(self, request):
        initial = super().get_changeform_initial_data(request)
        initial["rule"] = "*"
        return initial

    def get_urls(self):
        return [
            path("test_rules/", self.test_rules),
            path(
                "simulate_rules<path:test_path>",
                self.simulate_rules,
            ),
            path("<str:object_id>/rule_up/", self.rule_up),
            path("<str:object_id>/rule_down/", self.rule_down),
            path("<str:object_id>/rule_start/", self.rule_start),
            path("<str:object_id>/rule_end/", self.rule_end),
            *super().get_urls(),
        ]

    def rule_up(self, request, object_id):
        self.model.objects.position_up(object_id)
        return HttpResponseRedirect("../../")

    def rule_down(self, request, object_id):
        self.model.objects.position_down(object_id)
        return HttpResponseRedirect("../../")

    def rule_start(self, request, object_id):
        self.model.objects.position_start(object_id)
        return HttpResponseRedirect("../../")

    def rule_end(self, request, object_id):
        self.model.objects.position_end(object_id)
        return HttpResponseRedirect("../../")

    def simulate_rules(self, request, test_path):
        rule_id = RulePath.objects.match_path_and_ip(test_path, get_ip(request))
        if rule_id:
            rule = Rule.objects.get(id=rule_id)
            if rule.action == RULE_ACTION.deny.value:
                raise PermissionDenied()

        elif get_default_action() == RULE_ACTION.deny.value:
            raise PermissionDenied()
        return HttpResponse(f"accessed: {test_path}")

    def test_rules(self, request):
        from django.contrib.messages import ERROR, INFO, SUCCESS, WARNING

        test_ip = request.POST.get("test_ip", None)
        if not test_ip:
            test_ip = get_ip(request)

        test_path = request.POST.get("test_path", None) or ""
        if test_path:
            rule_id = RulePath.objects.match_path_and_ip(test_path, test_ip)
            self.message_user(
                request,
                f"Parameters: ip: {test_ip}, path: {test_path}",
                level=INFO,
            )
        else:
            rule_id = Rule.objects.match_ip(test_ip)
            self.message_user(
                request,
                f"Parameters: ip: {test_ip}",
                level=INFO,
            )
        if rule_id:
            rule = Rule.objects.get(id=rule_id)
            self.message_user(
                request,
                f"Matched rule: {rule.name}, action: {RULE_ACTION[rule.action]}",
                level=SUCCESS if rule.action == RULE_ACTION.allow.value else WARNING,
            )
        else:
            self.message_user(request, "No rule matched", level=ERROR)

        return HttpResponseRedirect("../")

    def delete_queryset(self, request, queryset):
        super().delete_queryset(request, queryset)
        Rule.objects.position_cleanup()


@admin.register(RulePath)
class RulePathAdmin(admin.ModelAdmin):
    list_display = ("rule", "path", "is_regex")

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
