# Generated by Django 5.0 on 2023-12-29 07:13

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("django_fast_iprestrict", "0003_migrate_rule"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="rule",
            name="rule",
        ),
        migrations.AlterModelOptions(
            name="rulepath",
            options={"verbose_name_plural": "Rule Pathes"},
        ),
    ]
