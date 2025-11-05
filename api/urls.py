# api/urls.py

from django.urls import path
from .views import (
    # Vistas de Auth
    RequestMagicLinkView,
    
    # Vistas de Perfil
    ProfileCreateView,
    UserProfileView,
    ProfilePictureUploadView,
    ProfileDetailView,

    # Vistas de Matching
    FirstMatchView,
)

urlpatterns = [
    # --- Auth ---
    path('auth/magic-link/', RequestMagicLinkView.as_view(), name='auth-magic-link-request'),
    
    # --- Profiles ---
    path('profiles/', ProfileCreateView.as_view(), name='profile-create'), # Legacy with password
    path('profiles/me/', UserProfileView.as_view(), name='profile-me'), # Get and Patch self
    path('profiles/me/picture/', ProfilePictureUploadView.as_view(), name='profile-picture-upload'),
    path('profiles/<int:user_id>/', ProfileDetailView.as_view(), name='profile-detail'), # Get public profile

    # --- Matching ---
    path('matches/first/', FirstMatchView.as_view(), name='first-match'),
]