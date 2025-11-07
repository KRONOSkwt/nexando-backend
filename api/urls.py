# api/urls.py

from django.urls import path
from .views import (
    RegisterView,
    LoginView,
    SetPasswordView,
    UserProfileView,
    ProfilePictureUploadView,
    ProfileDetailView,
    FirstMatchView,
)

urlpatterns = [
    # --- Auth (ARQUITECTURA HÍBRIDA FINAL) ---
    path('auth/register/', RegisterView.as_view(), name='auth-register'),
    path('auth/login/', LoginView.as_view(), name='auth-login'), # Para magic link de login
    path('auth/magic-link/set-password/', SetPasswordView.as_view(), name='auth-set-password'),
    
    # --- Profiles ---
    path('profiles/me/', UserProfileView.as_view(), name='profile-me'),
    path('profiles/me/picture/', ProfilePictureUploadView.as_view(), name='profile-picture-upload'),
    path('profiles/<int:user_id>/', ProfileDetailView.as_view(), name='profile-detail'),

    # --- Matching ---
    path('matches/first/', FirstMatchView.as_view(), name='first-match'),
]