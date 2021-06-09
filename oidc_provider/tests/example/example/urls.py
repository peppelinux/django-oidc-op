"""example URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.2/topics/http/urls/
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
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path

OIDC_URL_PREFIX = getattr(settings, 'OIDC_URL_PREFIX', '')

urlpatterns = [
    path('admin/', admin.site.urls),
]

urlpatterns += static(settings.STATIC_URL,
                      document_root=settings.STATIC_ROOT)

if 'oidc_provider' in settings.INSTALLED_APPS:
    import oidc_provider.urls
    from oidc_provider.views import well_known
    urlpatterns += path('.well-known/<str:service>',
                        well_known, name="oidc_op_well_known"),
    urlpatterns += path(f'{OIDC_URL_PREFIX}',
                        include((oidc_provider.urls, 'oidc_op',))),
