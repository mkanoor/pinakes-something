"""asc URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.urls import include, path
from django.conf import settings
from django.conf.urls.static import static
from social_django import urls as social_urls
from drf_spectacular.views import (
    SpectacularJSONAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)

from pinakes.main.auth import urls as auth_urls
from pinakes.main.common import urls as common_urls
from pinakes.main.catalog.urls import (
    router as catalog_router,
    urls_views as catalog_views,
)
from pinakes.main.approval.urls import (
    router as approval_router,
    urls_views as approval_views,
)
from pinakes.main.inventory.urls import (
    router as inventory_router,
    urls_views as inventory_views,
)


def _filter_by_view(urls_views, pattern):
    name = pattern.name
    if name in urls_views:
        if urls_views[name] is None:
            return False
        pattern.callback = urls_views[name]
    return True


API_PATH_PREFIX = settings.CATALOG_API_PATH_PREFIX.strip("/")
API_VER = "v1"
api_prefix = f"{API_PATH_PREFIX}/{API_VER}/"

approval_urls = [
    p for p in approval_router.urls if _filter_by_view(approval_views, p)
]
catalog_urls = [
    p for p in catalog_router.urls if _filter_by_view(catalog_views, p)
]
inventory_urls = [
    p for p in inventory_router.urls if _filter_by_view(inventory_views, p)
]

site_auth_urls = [
    path("", include((auth_urls, "api"), namespace="auth")),
    path("", include(social_urls, namespace="social")),
]


urlpatterns = [
    path(
        f"{api_prefix}schema/openapi.json",
        SpectacularJSONAPIView.as_view(),
        name="schema",
    ),
    path(
        f"{api_prefix}schema/swagger-ui/",
        SpectacularSwaggerView.as_view(url_name="schema"),
        name="swagger-ui",
    ),
    path(
        f"{api_prefix}schema/redoc/",
        SpectacularRedocView.as_view(url_name="schema"),
        name="redoc",
    ),
    path(f"{API_PATH_PREFIX}/auth/", include(site_auth_urls)),
    path(api_prefix, include((approval_urls, "api"), namespace="approval")),
    path(api_prefix, include((catalog_urls, "api"), namespace="catalog")),
    path(api_prefix, include((inventory_urls, "api"), namespace="inventory")),
    path(api_prefix, include((common_urls, "api"), namespace="common")),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
