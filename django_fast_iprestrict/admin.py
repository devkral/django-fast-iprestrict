from django.contrib import admin
from django.http import HttpResponseRedirect
from django.urls import path
from django.utils.html import format_html

from .models import Rule, RulePath
from .utils import get_ip

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
            path("test_rules/<path:test_path>", self.test_rules),
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

    def test_rules(self, request, test_path=None):
        from django.contrib.messages import ERROR, INFO, SUCCESS, WARNING

        test_ip = request.POST.get("test_ip", None)
        if not test_ip:
            test_ip = get_ip(request)

        if test_path is None:
            back_count = 1
            test_path = request.POST.get("test_path", None) or ""
        else:
            back_count = test_path.count("/") + 1
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
                f"Matched rule: {rule.name}, action: {Rule.ACTION[rule.action]}",
                level=SUCCESS if rule.action == "a" else WARNING,
            )
        else:
            self.message_user(request, "No rule matched", level=ERROR)

        return HttpResponseRedirect("../" * back_count)

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
