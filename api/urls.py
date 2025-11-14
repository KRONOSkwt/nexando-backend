from django.urls import path
from .views import (
    ValidateEmailView,
    RegisterView,
    LoginView,
    SetPasswordView,
    UserProfileView,
    ProfilePictureUploadView,
    ProfileDetailView,
    FirstMatchView,
    RecommendationView,
)

urlpatterns = [
    path('auth/validate-email/', ValidateEmailView.as_view(), name='auth-validate-email'),
    path('auth/register/', RegisterView.as_view(), name='auth-register'),
    path('auth/login/', LoginView.as_view(), name='auth-login'),
    path('auth/magic-link/set-password/', SetPasswordView.as_view(), name='auth-set-password'),
    path('profiles/me/', UserProfileView.as_view(), name='profile-me'),
    path('profiles/me/picture/', ProfilePictureUploadView.as_view(), name='profile-picture-upload'),
    path('profiles/<int:user_id>/', ProfileDetailView.as_view(), name='profile-detail'),
    path('matches/recommendations/', RecommendationView.as_view(), name='match-recommendations'),
    path('matches/first/', FirstMatchView.as_view(), name='first-match'),
]