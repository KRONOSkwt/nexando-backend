from django.urls import path
from .views import (
    # Vistas de Autenticación (v1.0 y v1.1)
    SignupView,
    ValidateEmailView,
    RegisterView,
    LoginView,
    SetPasswordView,
    PasswordResetRequestView,
    PasswordResetConfirmView,
    GoogleLoginView,
    
    # Vistas de Perfil
    UserProfileView,
    ProfilePictureUploadView,
    ProfileDetailView,
    
    # Vistas de Matching y Conexiones
    RecommendationView,
    MatchActionView,
    ConnectionListView,
    
    # Vistas de Chat
    SendMessageView,
    ConversationView,
    
    # Vistas de Funcionalidades v1.1
    AIChatView,
    FeedbackView,
    
    # Nuevo: Maestro de intereses
    InterestListView
)

urlpatterns = [
    # -------------------------------------------------------------------------
    # BLOQUE 1: AUTENTICACIÓN Y ONBOARDING
    # -------------------------------------------------------------------------
    
    # Registro Clásico (Email + Password) -> Retorna tokens
    path('auth/signup/', SignupView.as_view(), name='auth-signup'),
    
    # Validación proactiva de disponibilidad de email
    path('auth/validate-email/', ValidateEmailView.as_view(), name='auth-validate-email'),
    
    # Registro Passwordless (Magic Link) -> Envía email
    path('auth/register/', RegisterView.as_view(), name='auth-register'),
    
    # Login Passwordless / Recuperación (Magic Link) -> Envía email
    path('auth/login/', LoginView.as_view(), name='auth-login'),
    
    # Confirmación de Magic Link y establecimiento de contraseña
    path('auth/magic-link/set-password/', SetPasswordView.as_view(), name='auth-set-password'),

    # -------------------------------------------------------------------------
    # BLOQUE 2: RECUPERACIÓN DE CONTRASEÑA Y SOCIAL LOGIN (v1.1)
    # -------------------------------------------------------------------------
    
    # Solicitar reseteo de contraseña (envía email con token)
    path('auth/password-reset/', PasswordResetRequestView.as_view(), name='password-reset-request'),
    
    # Confirmar reseteo con token y nueva contraseña
    path('auth/password-reset/confirm/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    
    # Login con Google (OAuth2) -> Recibe token de Google, retorna tokens JWT
    path('auth/google/', GoogleLoginView.as_view(), name='google-login'),

    # -------------------------------------------------------------------------
    # BLOQUE 3: GESTIÓN DE PERFILES
    # -------------------------------------------------------------------------
    
    # Ver y Editar el perfil propio
    path('profiles/me/', UserProfileView.as_view(), name='profile-me'),
    
    # Subir foto de perfil (Optimización WebP + Cloudinary)
    path('profiles/me/picture/', ProfilePictureUploadView.as_view(), name='profile-picture-upload'),
    
    # Ver perfil público de otro usuario (requiere conexión o interacción previa)
    path('profiles/<int:user_id>/', ProfileDetailView.as_view(), name='profile-detail'),

    # -------------------------------------------------------------------------
    # BLOQUE 4: MOTOR DE MATCHING Y CONEXIONES
    # -------------------------------------------------------------------------
    
    # Obtener recomendaciones (Carrusel)
    path('matches/recommendations/', RecommendationView.as_view(), name='match-recommendations'),
    
    # Realizar acción (Like/Pass)
    path('matches/action/', MatchActionView.as_view(), name='match-action'),
    
    # Listar conexiones confirmadas (Inbox)
    path('connections/', ConnectionListView.as_view(), name='connection-list'),

    # -------------------------------------------------------------------------
    # BLOQUE 5: CHAT Y MENSAJERÍA
    # -------------------------------------------------------------------------
    
    # Enviar mensaje nuevo
    path('messages/', SendMessageView.as_view(), name='send-message'),
    
    # Obtener historial de conversación con un usuario específico
    path('messages/<int:user_id>/', ConversationView.as_view(), name='conversation-history'),

    # -------------------------------------------------------------------------
    # BLOQUE 6: NUEVAS FUNCIONALIDADES (v1.1)
    # -------------------------------------------------------------------------
    
    # Chat con Inteligencia Artificial (ChatGPT)
    path('ai/chat/', AIChatView.as_view(), name='ai-chat'),
    
    # Envío de Feedback / Reportes de Bug
    path('feedback/', FeedbackView.as_view(), name='feedback'),

    # Maestro de Intereses (Cacheado)
    path('interests/', InterestListView.as_view(), name='interest-list'),
]