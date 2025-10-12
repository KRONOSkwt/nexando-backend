# nexando_backend/urls.py

from django.contrib import admin
from django.urls import path, include # Asegúrate de que 'include' esté importado

urlpatterns = [
    path('admin/', admin.site.urls),
    # Cualquier petición a "api/v1/" será manejada por nuestra app api
    path('api/v1/', include('api.urls')),
]