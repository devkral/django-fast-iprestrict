from django import forms
from django.core import validators

from .validators import validate_methods, validate_path


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
        validators=[validate_path],
        required=False,
        help_text="leave empty to test ip addresses only",
    )
    test_method = forms.CharField(
        validators=[validate_methods],
        required=False,
        help_text="leave empty to don't use method testing",
    )
    test_ratelimit_group = forms.CharField(
        validators=[validators.MinLengthValidator(1)],
        required=False,
        help_text="leave empty to not simulate a query from ratelimit apply_fn",
    )

    @property
    def has_data(self) -> bool:
        return bool(set(self.changed_data).difference({"link_back"}))
