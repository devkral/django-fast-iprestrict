from django import forms
from django.core import validators


class LinkBackForm(forms.Form):
    link_back = forms.CharField(initial="../", widget=forms.HiddenInput, required=False)


class TestRulesForm(LinkBackForm):
    field_template_name = "admin/django_fast_iprestrict/test_rules_field.html"
    test_ip = forms.CharField(
        validators=[validators.validate_ipv46_address],
        required=False,
        help_text="leave empty to use current ip address",
    )
    test_path = forms.CharField(
        validators=[],
        required=False,
        help_text="leave empty to test ip addresses only",
    )
    test_method = forms.CharField(
        validators=[validators.RegexValidator()],
        required=False,
        help_text="leave empty to don't use method testing",
    )
