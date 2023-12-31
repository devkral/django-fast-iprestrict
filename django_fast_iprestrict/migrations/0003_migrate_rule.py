# Generated by Django 5.0 on 2023-12-29 06:26

from django.db import migrations


def forwards_func(apps, schema_editor):
    Rule = apps.get_model("django_fast_iprestrict", "Rule")
    RuleNetwork = apps.get_model("django_fast_iprestrict", "RuleNetwork")
    db_alias = schema_editor.connection.alias
    for rule in Rule.objects.using(db_alias).exclude(rule="*"):
        RuleNetwork.objects.using(db_alias).create(
            rule=rule, network=rule.rule, is_active=True
        )


def reverse_func(apps, schema_editor):
    RuleNetwork = apps.get_model("django_fast_iprestrict", "RuleNetwork")
    db_alias = schema_editor.connection.alias
    # the last active rule wins
    for network in (
        RuleNetwork.objects.using(db_alias)
        .select_related("rule")
        .filter(is_active=True)
    ):
        network.rule.rule = network
        network.rule.save()


class Migration(migrations.Migration):
    dependencies = [
        ("django_fast_iprestrict", "0002_split_rule"),
    ]

    operations = [
        migrations.RunPython(forwards_func, reverse_func),
    ]
