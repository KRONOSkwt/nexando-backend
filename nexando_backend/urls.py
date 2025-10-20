# nexando_backend/urls.py

from django.contrib import admin
from django.urls import path, include

# --- Importa las vistas de Simple JWT ---
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

urlpatterns = [
    path('admin/', admin.site.urls),

    # Rutas de nuestra API de perfiles
    path('api/v1/', include('api.urls')),

    # 1. Ruta para obtener un par de tokens (login)
    path('api/v1/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    
    # 2. Ruta para refrescar un token de acceso
    path('api/v1/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]