# Generated by Django 3.2.5 on 2021-09-03 14:37

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("main", "0005_auto_20210827_1556"),
    ]

    operations = [
        migrations.AlterField(
            model_name="serviceinventory",
            name="source_created_at",
            field=models.DateTimeField(null=True),
        ),
        migrations.AlterField(
            model_name="serviceinventory",
            name="source_updated_at",
            field=models.DateTimeField(null=True),
        ),
        migrations.AlterField(
            model_name="serviceoffering",
            name="source_created_at",
            field=models.DateTimeField(null=True),
        ),
        migrations.AlterField(
            model_name="serviceoffering",
            name="source_updated_at",
            field=models.DateTimeField(null=True),
        ),
        migrations.AlterField(
            model_name="serviceofferingnode",
            name="source_created_at",
            field=models.DateTimeField(null=True),
        ),
        migrations.AlterField(
            model_name="serviceofferingnode",
            name="source_updated_at",
            field=models.DateTimeField(null=True),
        ),
        migrations.AlterField(
            model_name="serviceplan",
            name="source_created_at",
            field=models.DateTimeField(null=True),
        ),
        migrations.AlterField(
            model_name="serviceplan",
            name="source_updated_at",
            field=models.DateTimeField(null=True),
        ),
        migrations.CreateModel(
            name="ServiceInstance",
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
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("source_created_at", models.DateTimeField(null=True)),
                ("source_updated_at", models.DateTimeField(null=True)),
                ("source_ref", models.CharField(max_length=32)),
                ("name", models.CharField(blank=True, max_length=255)),
                ("extra", models.JSONField(null=True)),
                ("external_url", models.CharField(blank=True, max_length=255)),
                (
                    "service_inventory",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        to="main.serviceinventory",
                    ),
                ),
                (
                    "service_offering",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        to="main.serviceoffering",
                    ),
                ),
                (
                    "service_plan",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        to="main.serviceplan",
                    ),
                ),
                (
                    "source",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="main.source",
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="main.tenant",
                    ),
                ),
            ],
            options={
                "abstract": False,
            },
        ),
    ]
