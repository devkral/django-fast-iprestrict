from django import forms
from django.core import validators
from django.forms.formsets import DELETION_FIELD_NAME

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


class ManagedForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.instance.managed_fields:
            field = self.fields.get(field)
            if field:
                field.disabled = True
                field.widget.attrs["title"] = "managed"

    def clean(self):
        ret = super().clean()
        if self.instance.managed_fields:
            # MUST pop deletion field for preventing deletion
            if ret.pop(DELETION_FIELD_NAME, False):
                raise forms.ValidationError("Cannot delete managed form")

        return ret
