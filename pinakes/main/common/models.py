from django.db import models


class Role(models.Model):
    name = models.CharField(max_length=255)


class Group(models.Model):
    id = models.CharField(max_length=255, primary_key=True)
    name = models.CharField(max_length=255)
    path = models.TextField(unique=True)

    last_sync_time = models.DateTimeField()
    parent = models.ForeignKey(
        "self", related_name="subgroups", on_delete=models.CASCADE, null=True
    )
    roles = models.ManyToManyField(Role)
