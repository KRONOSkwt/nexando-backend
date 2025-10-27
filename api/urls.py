# api/urls.py

from django.urls import path
from .views import (
    ProfileCreateView,
    UserProfileView,
    ProfileDetailView,
    FirstMatchView,
    ProfilePictureUploadView,
)

urlpatterns = [
    # Perfiles
    path('profiles/', ProfileCreateView.as_view(), name='profile-create'),
    path('profiles/me/', UserProfileView.as_view(), name='profile-me'),
    path('profiles/me/picture/', ProfilePictureUploadView.as_view(), name='profile-picture-upload'), # NUEVA
    path('profiles/<int:user_id>/', ProfileDetailView.as_view(), name='profile-detail'),

    # Matching
    path('matches/first/', FirstMatchView.as_view(), name='first-match'), # NUEVA
]