from rest_framework import serializers

import jwt

from django.conf import settings
from django.contrib.auth.models import User
from drf_spectacular.utils import extend_schema_field


class CurrentUserSerializer(serializers.ModelSerializer):
    roles = serializers.SerializerMethodField("get_roles")

    class Meta:
        model = User
        fields = ("username", "first_name", "last_name", "roles")

    @extend_schema_field(field={"type": "array", "items": {"type": "string"}})
    def get_roles(self, obj):
        request = self.context.get("request")
        extra_data = request.keycloak_user.extra_data
        jot = jwt.decode(
            extra_data["access_token"], options={"verify_signature": False}
        )
        roles = (
            jot.get("resource_access", {})
            .get(settings.KEYCLOAK_CLIENT_ID, {})
            .get("roles", [])
        )
        return roles