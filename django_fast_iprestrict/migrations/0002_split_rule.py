# Generated by Django 5.0 on 2023-12-29 06:22

import django.db.models.deletion
from django.db import migrations, models

import django_fast_iprestrict.validators


class Migration(migrations.Migration):
    dependencies = [
        ("django_fast_iprestrict", "0001_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="rulepath",
            name="rule",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="pathes",
                to="django_fast_iprestrict.rule",
            ),
        ),
        migrations.CreateModel(
            name="RuleNetwork",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("is_active", models.BooleanField(blank=True, default=True)),
                (
                    "network",
                    models.CharField(
                        max_length=50,
                        validators=[django_fast_iprestrict.validators.validate_network],
                    ),
                ),
                (
                    "rule",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="networks",
                        to="django_fast_iprestrict.rule",
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="RuleSource",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("is_active", models.BooleanField(blank=True, default=True)),
                (
                    "rule",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="sources",
                        to="django_fast_iprestrict.rule",
                    ),
                ),
                (
                    "generator_fn",
                    models.CharField(blank=True, default="", max_length=200),
                ),
                (
                    "interval",
                    models.PositiveIntegerField(
                        blank=True,
                        default=django_fast_iprestrict.utils.get_default_interval,
                    ),
                ),
            ],
        ),
    ]
