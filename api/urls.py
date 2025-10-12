# api/urls.py

from django.urls import path
from .views import ProfileDetailView

urlpatterns = [
    # La ruta que espera el frontend: GET /api/v1/profiles/1/
    path('profiles/<int:user_id>/', ProfileDetailView.as_view(), name='profile-detail'),
]