"""provides a common implementation of get_queryset method in viewset"""
import logging
from django.http import Http404
from django.shortcuts import get_object_or_404
from rest_framework.exceptions import PermissionDenied

from pinakes.main.models import Tenant

logger = logging.getLogger("catalog")


class QuerySetMixin:
    """
    A Mixin class to be inherited by a customer ViewSet class
    """

    def get_queryset(self):
        """filter by current tenant and query_lookup_key, order by queryset_order_by"""

        parent_field_names = getattr(self, "parent_field_names", [])
        queryset_order_by = getattr(self, "queryset_order_by", None)
        serializer_class = self.get_serializer_class() or self.serializer_class
        model_cls = serializer_class.Meta.model
        queryset = serializer_class.Meta.model.objects.filter(
            tenant=Tenant.current()
        )
        keycloak_field = getattr(model_cls, "KEYCLOAK_PARENT_FIELD", "pk")
        result = self.get_keycloak_resource_ids()
        if result:
            if not "all" in result:
                kwargs = {f"{keycloak_field}__in": result}
                logger.info(kwargs)
                queryset = queryset.filter(**kwargs)

        for parent_field_name in parent_field_names:
            parent_lookup_key = f"{parent_field_name}_id"
            if parent_lookup_key in self.kwargs:
                try:
                    self._check_parent_permission(
                        model_cls,
                        parent_field_name,
                        self.kwargs[parent_lookup_key],
                    )
                    queryset = queryset.filter(
                        **{parent_field_name: self.kwargs[parent_lookup_key]}
                    )
                except ValueError as ex:
                    raise Http404 from ex
        if queryset_order_by is not None:
            queryset = queryset.order_by(queryset_order_by)
        return queryset

    def get_keycloak_resource_ids(self):
        """Get the result set of allowed keycloak resources"""

        serializer_class = self.get_serializer_class() or self.serializer_class
        model_cls = serializer_class.Meta.model

        keycloak_type = getattr(model_cls, "KEYCLOAK_TYPE", None)
        # For models that don't have KEYCLOAK_TYPE ignore them
        if not keycloak_type:
            return None
        self.request.user.get_all_permissions()

        if hasattr(self.request.user, "_keycloak_authz_resources"):
            return self._get_ids(keycloak_type)

        return None

    def _get_ids(self, keycloak_type):
        ids = set()
        perm = f"{keycloak_type}:read"
        for authz_res in self.request.user._keycloak_authz_resources:
            if authz_res.rsname.startswith(keycloak_type):
                if perm in authz_res.scopes:
                    ids.add(authz_res.rsname.split(":").pop())

        return ids

    def _check_parent_permission(self, model, field, parent_id):
        # Check if we have access to the parent object
        parent_model = model._meta.get_field(field).related_model
        parent_obj = get_object_or_404(parent_model, pk=parent_id)
        permission_object = getattr(parent_model, "PERMISSION_OBJECT", None)
        if permission_object:
            parent_obj = getattr(parent_obj, permission_object)
            parent_model = parent_obj.__class__

        perm = f"{parent_model._meta.app_label}.view_{parent_model._meta.model_name}"

        if not self.request.user.has_perm(perm, parent_obj):
            logger.warning("No access to parent object")
            raise PermissionDenied("No access to parent object")
