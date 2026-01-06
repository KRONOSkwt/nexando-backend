from django.urls import path
from .views import (
    SignupView,
    ValidateEmailView,
    RegisterView,
    LoginView,
    SetPasswordView,
    UserProfileView,
    ProfilePictureUploadView,
    ProfileDetailView,
    RecommendationView,
    MatchActionView,
    ConnectionListView,
    SendMessageView,
    ConversationView
)

urlpatterns = [
    # --- Auth Híbrida ---
    path('auth/signup/', SignupView.as_view(), name='auth-signup'), # Nuevo flujo clásico
    path('auth/validate-email/', ValidateEmailView.as_view(), name='auth-validate-email'),
    path('auth/register/', RegisterView.as_view(), name='auth-register'), # Magic Link
    path('auth/login/', LoginView.as_view(), name='auth-login'),
    path('auth/magic-link/set-password/', SetPasswordView.as_view(), name='auth-set-password'),
    
    # --- Profiles ---
    path('profiles/me/', UserProfileView.as_view(), name='profile-me'),
    path('profiles/me/picture/', ProfilePictureUploadView.as_view(), name='profile-picture-upload'),
    path('profiles/<int:user_id>/', ProfileDetailView.as_view(), name='profile-detail'),

    # --- Matching ---
    path('matches/recommendations/', RecommendationView.as_view(), name='match-recommendations'),
    path('matches/action/', MatchActionView.as_view(), name='match-action'),
    path('connections/', ConnectionListView.as_view(), name='connection-list'),

    # --- Chat ---
    path('messages/', SendMessageView.as_view(), name='send-message'),
    path('messages/<int:user_id>/', ConversationView.as_view(), name='conversation-history'),
]