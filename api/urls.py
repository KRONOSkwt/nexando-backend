# api/urls.py

from django.urls import path
# Importa la nueva UserProfileView
from .views import ProfileDetailView, ProfileCreateView, UserProfileView

urlpatterns = [
    # Ruta para CREAR un perfil (POST)
    path('profiles/', ProfileCreateView.as_view(), name='profile-create'),
    
    path('profiles/me/', UserProfileView.as_view(), name='profile-me'),

    # Ruta para LEER un perfil público específico (GET)
    path('profiles/<int:user_id>/', ProfileDetailView.as_view(), name='profile-detail'),
]