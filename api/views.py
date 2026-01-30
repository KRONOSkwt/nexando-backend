import os
import logging
from io import BytesIO
from PIL import Image
from datetime import timedelta

# Django Imports
from django.core.files.base import ContentFile
from django.core.cache import cache
from django.shortcuts import get_object_or_404
from django.db import IntegrityError, transaction
from django.db.models import Count, Q
from django.contrib.auth.models import User
from django.conf import settings
from django.core.validators import validate_email
from django.core.exceptions import ValidationError as DjangoValidationError 
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str

# DRF Imports
from rest_framework import generics, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from rest_framework.exceptions import PermissionDenied

# Third Party
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import openai

# Local Imports
from .models import Profile, Interest, UserInterest, MatchAction, Connection, Message, Feedback
from .serializers import (
    ProfileSerializer, 
    SignupSerializer, 
    ProfilePictureSerializer,
    MessageSerializer,
    GoogleLoginSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
    AIChatSerializer,
    FeedbackSerializer
)

logger = logging.getLogger(__name__)

# --- CONSTANTES DE SEGURIDAD ---
MAX_PROFILE_PICTURE_SIZE = 5 * 1024 * 1024 
MAX_IMAGE_PIXELS = 4096 * 4096

"""
BLOQUE: UTILIDADES Y SERVICIOS EXTERNOS
"""

def send_match_notification_async(user1, user2):
    """
    TODO: Mover a Celery en v1.2 para procesamiento asíncrono real.
    """
    logger.info(f"Match event triggered: {user1.username} <-> {user2.username}")


def send_email_via_sendgrid(to_email, subject, html_content):
    """
    Servicio centralizado de envío de correos vía SendGrid.
    """
    api_key = settings.SENDGRID_API_KEY
    from_email = settings.DEFAULT_FROM_EMAIL
    
    if not api_key or not from_email:
        logger.critical("Email configuration missing in environment variables.")
        return 

    message = Mail(
        from_email=from_email, 
        to_emails=to_email, 
        subject=subject, 
        html_content=html_content
    )
    try:
        sg = SendGridAPIClient(api_key)
        sg.send(message)
    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {str(e)}", exc_info=True)


def send_magic_link_email(user):
    """
    Genera y envía el token de acceso para el flujo Passwordless.
    """
    token = AccessToken.for_user(user)
    token.set_exp(lifetime=timedelta(minutes=10))
    
    base_url = os.environ.get('FRONTEND_URL', "http://localhost:3000")
    magic_link_url = f"{base_url}/auth/magic-link/verify/?token={str(token)}"
    
    html = f'<strong>Welcome to Nexando!</strong><br>Click <a href="{magic_link_url}">here</a> to continue.'
    send_email_via_sendgrid(user.email, 'Your Magic Link to Nexando.ai', html)


"""
BLOQUE: VISTAS DE AUTENTICACIÓN (REGISTRO Y LOGIN)
"""

class SignupView(generics.CreateAPIView):
    """
    Registro clásico con Email y Password.
    """
    permission_classes = [AllowAny]
    serializer_class = SignupSerializer
    throttle_scope = 'auth'

    def create(self, request, *args, **kwargs):
        email = request.data.get('email')
        try:
            validate_email(email)
        except DjangoValidationError:
            return Response({'error': 'Invalid email format'}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(username=email).exists():
             return Response({'error': 'Email already registered. Please login.'}, status=status.HTTP_409_CONFLICT)
        
        try:
            return super().create(request, *args, **kwargs)
        except Exception as e:
            logger.error("Signup error", exc_info=True)
            return Response({'error': 'Registration failed due to server error.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ValidateEmailView(APIView):
    """
    Verificación proactiva de disponibilidad de email.
    """
    permission_classes = [AllowAny]
    throttle_scope = 'auth'

    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        if not email:
            return Response({'error': 'Email required'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            validate_email(email)
        except DjangoValidationError:
            return Response({'error': 'Invalid email format'}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(username=email).exists():
            return Response({'error': 'Email already registered'}, status=status.HTTP_409_CONFLICT)
        
        return Response(status=status.HTTP_204_NO_CONTENT)


class RegisterView(APIView):
    """
    Registro Passwordless (Onboarding inicial).
    """
    permission_classes = [AllowAny]
    throttle_scope = 'auth'

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        first_name = request.data.get('first_name')
        interests_data = request.data.get('interests', [])
        
        if not email or not first_name or not first_name.strip():
            return Response({'error': 'Email and first name are required.'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            validate_email(email)
        except DjangoValidationError:
            return Response({'error': 'Invalid email format'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.create_user(username=email, email=email, is_active=False)
            profile = Profile.objects.create(user=user, first_name=first_name.strip())
            
            seen_interests = set()
            for item in interests_data:
                name = item.get('name', '').strip().title() if isinstance(item, dict) else str(item).strip().title()
                if name and name not in seen_interests:
                    seen_interests.add(name)
                    interest_obj, _ = Interest.objects.get_or_create(name=name)
                    is_primary = item.get('is_primary', False) if isinstance(item, dict) else False
                    UserInterest.objects.create(profile=profile, interest=interest_obj, is_primary=is_primary)
            
            send_magic_link_email(user)
            return Response({'detail': 'Magic link sent to your email.'}, status=status.HTTP_201_CREATED)
        except Exception as e:
            logger.error("RegisterView Error", exc_info=True)
            return Response({'error': 'Service temporarily unavailable'}, status=status.HTTP_502_BAD_GATEWAY)


class LoginView(APIView):
    """
    Solicitud de Magic Link para usuarios existentes.
    """
    permission_classes = [AllowAny]
    throttle_scope = 'auth'

    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        if not email:
            return Response({'error': 'Email required'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            validate_email(email)
        except DjangoValidationError:
            return Response({'detail': 'Link sent if account exists'}, status=status.HTTP_200_OK)

        try:
            user = User.objects.get(username=email)
            send_magic_link_email(user)
        except User.DoesNotExist:
            pass
            
        return Response({'detail': 'If an account with that email exists, a link has been sent.'}, status=status.HTTP_200_OK)


class SetPasswordView(APIView):
    """
    Paso final del Onboarding: Establecer contraseña y activar cuenta.
    """
    permission_classes = [AllowAny]
    throttle_scope = 'auth'

    def post(self, request, *args, **kwargs):
        token_str = request.data.get('token')
        password = request.data.get('password')
        
        if not token_str or not password:
            return Response({'error': 'Token and password are required.'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            token = AccessToken(token_str)
            token.verify()
            
            user = User.objects.get(id=token['user_id'])
            user.set_password(password)
            user.is_active = True
            user.save()
            
            # Garantizar perfil
            Profile.objects.get_or_create(user=user, defaults={'first_name': user.first_name or 'User'})
            
            tokens = RefreshToken.for_user(user)
            return Response({
                'refresh': str(tokens),
                'access': str(tokens.access_token)
            }, status=status.HTTP_200_OK)
        except (TokenError, InvalidToken):
            return Response({'error': 'Invalid or expired token'}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            logger.error("SetPassword Error", exc_info=True)
            return Response({'error': 'An internal error occurred'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GoogleLoginView(APIView):
    """
    Login Social con Google. Refactorizado para mayor robustez y prevención de Error 500.
    """
    permission_classes = [AllowAny]
    throttle_scope = 'auth'

    def post(self, request):
        serializer = GoogleLoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        token = serializer.validated_data['token']
        GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
        
        try:
            idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), GOOGLE_CLIENT_ID)
            email = idinfo['email']
            first_name = idinfo.get('given_name', 'User')
            
            with transaction.atomic():
                # 1. Intentamos obtener el usuario por email
                user = User.objects.filter(email=email).first()
                created = False
                
                if not user:
                    # 2. Si no existe, lo creamos. Usamos email como username.
                    user = User.objects.create_user(
                        username=email, 
                        email=email, 
                        is_active=True, 
                        first_name=first_name
                    )
                    created = True
                
                # 3. Garantizar que el perfil existe siempre (Pilar I fix)
                Profile.objects.get_or_create(
                    user=user, 
                    defaults={'first_name': first_name}
                )
            
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'is_new_user': created
            }, status=status.HTTP_200_OK)

        except ValueError:
            return Response({'error': 'Invalid Google Token'}, status=status.HTTP_400_BAD_REQUEST)
        except IntegrityError as e:
            logger.error(f"Google Integrity Conflict: {e}")
            return Response({'error': 'A database conflict occurred during login.'}, status=status.HTTP_409_CONFLICT)
        except Exception as e:
            logger.error(f"Google Login Error: {e}", exc_info=True)
            return Response({'error': 'Authentication failed due to server error.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


"""
BLOQUE: RECUPERACIÓN DE CONTRASEÑA
"""

class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]
    throttle_scope = 'auth'

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        email = serializer.validated_data['email']
        try:
            user = User.objects.get(email=email)
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            
            base_url = os.environ.get('FRONTEND_URL', "http://localhost:3000")
            reset_link = f"{base_url}/auth/reset-password?uid={uid}&token={token}"
            
            html = f'<strong>Password Reset</strong><br>Click <a href="{reset_link}">here</a> to set a new password.'
            send_email_via_sendgrid(email, 'Reset your Nexando Password', html)
        except User.DoesNotExist:
            pass 
            
        return Response({'detail': 'If the email exists, a reset link has been sent.'}, status=status.HTTP_200_OK)


class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]
    throttle_scope = 'auth'

    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        uid = serializer.validated_data['uid']
        token = serializer.validated_data['token']
        password = serializer.validated_data['new_password']

        try:
            user_id = force_str(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=user_id)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({'error': 'Invalid link'}, status=status.HTTP_400_BAD_REQUEST)

        if not default_token_generator.check_token(user, token):
            return Response({'error': 'Invalid or expired token'}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(password)
        user.save()
        return Response({'detail': 'Password reset successful.'}, status=status.HTTP_200_OK)


"""
BLOQUE: GESTIÓN DE PERFIL
"""

class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        profile, created = Profile.objects.get_or_create(
            user=request.user, 
            defaults={'first_name': request.user.first_name or 'User'}
        )
        serializer = ProfileSerializer(profile)
        return Response(serializer.data)
    
    def patch(self, request, format=None):
        profile, created = Profile.objects.get_or_create(user=request.user)
        serializer = ProfileSerializer(profile, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            cache.delete(f"user_{request.user.id}_interests") 
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ProfilePictureUploadView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)
    throttle_scope = 'uploads'

    def put(self, request, format=None):
        if 'profile_picture' not in request.FILES:
            return Response({'error': 'No file submitted'}, status=status.HTTP_400_BAD_REQUEST)
            
        file_obj = request.FILES['profile_picture']
        
        if file_obj.size > MAX_PROFILE_PICTURE_SIZE:
            return Response({'error': 'File too large (max 5MB)'}, status=status.HTTP_400_BAD_REQUEST)
            
        allowed = ['jpg', 'jpeg', 'png', 'webp']
        if file_obj.name.split('.')[-1].lower() not in allowed:
            return Response({'error': 'Invalid file type'}, status=status.HTTP_400_BAD_REQUEST)

        profile = request.user.profile
        try:
            img = Image.open(file_obj)
            img.verify()
            file_obj.seek(0)
            img = Image.open(file_obj)
            
            if img.width * img.height > MAX_IMAGE_PIXELS:
                return Response({'error': 'Dimensions too large'}, status=status.HTTP_400_BAD_REQUEST)
                
            buffer = BytesIO()
            img.save(buffer, format='WEBP', quality=85)
            buffer.seek(0)
            
            filename = f'{profile.user.id}_{os.path.splitext(file_obj.name)[0]}.webp'
            profile.profile_picture_url.save(filename, ContentFile(buffer.read()), save=True)
            
            return Response(ProfilePictureSerializer(profile).data)
        except Exception:
            logger.error("Upload Error", exc_info=True)
            return Response({'error': 'Failed to process image'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ProfileDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, user_id, format=None):
        target = get_object_or_404(User, pk=user_id)
        req = request.user
        
        if req.id == target.id:
            return Response(ProfileSerializer(target.profile).data)
            
        u1, u2 = sorted([req.id, target.id])
        if Connection.objects.filter(user1_id=u1, user2_id=u2).exists():
            return Response(ProfileSerializer(target.profile).data)
            
        if MatchAction.objects.filter(actor=target, target=req, action='like').exists():
             return Response(ProfileSerializer(target.profile).data)

        return Response({'detail': 'Not found'}, status=status.HTTP_404_NOT_FOUND)


"""
BLOQUE: MATCHING Y CONEXIONES
"""

class RecommendationView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ProfileSerializer

    def get_queryset(self):
        user = self.request.user
        cache_key = f"user_{user.id}_interests"
        my_ids = cache.get(cache_key)
        
        if not my_ids:
            my_ids = list(user.profile.userinterest_set.values_list('interest_id', flat=True))
            cache.set(cache_key, my_ids, timeout=60)
            
        interacted = list(MatchAction.objects.filter(actor=user).values_list('target_id', flat=True))
        
        queryset = Profile.objects.filter(
            interests__id__in=my_ids
        ).exclude(user=user).exclude(user_id__in=interacted).distinct()
        
        return queryset.annotate(
            common_count=Count('interests', filter=Q(interests__id__in=my_ids))
        ).order_by('-common_count', '?')


class MatchActionView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_scope = 'messages'

    def post(self, request, *args, **kwargs):
        actor = request.user
        target_id = request.data.get('target_id')
        action = request.data.get('action')
        
        if not target_id or action not in ['like', 'pass']:
            return Response({'error': 'Invalid data'}, status=status.HTTP_400_BAD_REQUEST)
            
        with transaction.atomic():
            try:
                target = User.objects.select_for_update().get(id=target_id)
            except User.DoesNotExist:
                return Response({'error': 'Not found'}, status=status.HTTP_404_NOT_FOUND)
                
            if actor.id == target.id:
                return Response({'error': 'Self action prohibited'}, status=status.HTTP_400_BAD_REQUEST)

            MatchAction.objects.update_or_create(actor=actor, target=target, defaults={'action': action})
            
            if action == 'like':
                if MatchAction.objects.filter(actor=target, target=actor, action='like').exists():
                    u1, u2 = sorted([actor.id, target.id])
                    try:
                        conn, cr = Connection.objects.get_or_create(user1_id=u1, user2_id=u2)
                    except IntegrityError:
                        conn = Connection.objects.get(user1_id=u1, user2_id=u2)
                        cr = False
                        
                    if cr:
                        send_match_notification_async(actor, target)
                        
                    return Response({'status': 'match', 'connection_id': conn.id}, status=status.HTTP_201_CREATED)
                    
        return Response({'status': action}, status=status.HTTP_200_OK)


class ConnectionListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ProfileSerializer

    def get_queryset(self):
        user = self.request.user
        conns = Connection.objects.filter(Q(user1=user) | Q(user2=user))
        partner_ids = [c.user2_id if c.user1_id == user.id else c.user1_id for c in conns]
        return Profile.objects.filter(user__id__in=partner_ids).select_related('user')


"""
BLOQUE: MENSAJERÍA (CHAT)
"""

class SendMessageView(generics.CreateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = MessageSerializer
    throttle_scope = 'messages'

    def perform_create(self, serializer):
        recipient = serializer.validated_data['recipient']
        u1, u2 = sorted([self.request.user.id, recipient.id])
        
        if not Connection.objects.filter(user1_id=u1, user2_id=u2).exists():
            raise PermissionDenied("You can only message users you have matched with.")
            
        serializer.save(sender=self.request.user)


class ConversationView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = MessageSerializer

    def get_queryset(self):
        user = self.request.user
        other_id = self.kwargs['user_id']
        u1, u2 = sorted([user.id, other_id])
        
        if not Connection.objects.filter(user1_id=u1, user2_id=u2).exists():
             raise PermissionDenied("Access denied to this conversation.")

        return Message.objects.filter(
            Q(sender=user, recipient_id=other_id) | 
            Q(sender_id=other_id, recipient=user)
        ).order_by('timestamp')


"""
BLOQUE: INTELIGENCIA ARTIFICIAL Y COMUNIDAD
"""

class AIChatView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_scope = 'messages'

    def post(self, request):
        serializer = AIChatSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user_message = serializer.validated_data['message']
        history = serializer.validated_data['history']
        api_key = os.environ.get('OPENAI_API_KEY')
        
        if not api_key:
            return Response({'error': 'AI Service unavailable'}, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        try:
            client = openai.OpenAI(api_key=api_key)
            messages_payload = [{"role": "system", "content": "Eres NexandoBot, un asistente útil para jóvenes profesionales."}]
            
            for msg in history[-4:]: 
                if 'role' in msg and 'content' in msg:
                    messages_payload.append(msg)
            
            messages_payload.append({"role": "user", "content": user_message})

            completion = client.chat.completions.create(
                model="gpt-3.5-turbo", 
                messages=messages_payload, 
                max_tokens=300
            )
            return Response({'reply': completion.choices[0].message.content}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"OpenAI API Error: {str(e)}")
            return Response({'error': 'AI is busy, try again later.'}, status=status.HTTP_502_BAD_GATEWAY)


class FeedbackView(generics.CreateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = FeedbackSerializer
    throttle_scope = 'uploads'

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)
        admin_email = os.environ.get('DEFAULT_FROM_EMAIL') 
        if admin_email:
            subject = f"New User Feedback: {self.request.user.username}"
            content = serializer.validated_data['content']
            send_email_via_sendgrid(admin_email, subject, content)