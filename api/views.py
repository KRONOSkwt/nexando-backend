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
from django.template.loader import render_to_string

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
BLOQUE: UTILIDADES Y SERVICIOS EXTERNOS (EMAIL & NOTIFICACIONES)
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
        response = sg.send(message)
        if response.status_code not in [200, 201, 202]:
            logger.error(f"SendGrid rejected mail: {response.body}")
    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {str(e)}", exc_info=True)


def get_email_content(lang, link_type, link_url):
    """
    Define los textos traducidos para los correos estéticos.
    """
    translations = {
        'en': {
            'magic_link': {
                'subject': 'Your Magic Link for Nexando.ai',
                'title': 'Welcome Back!',
                'message_body': 'Click the button below to securely access your account. No password required.',
                'cta_text': 'Sign in to Nexando',
                'disclaimer': 'This link is valid for 10 minutes. If you did not request this, please ignore this email.'
            },
            'password_reset': {
                'subject': 'Reset your Nexando Password',
                'title': 'Reset Your Password',
                'message_body': 'We received a request to reset your password. Click below to choose a new one.',
                'cta_text': 'Reset Password',
                'disclaimer': 'If you did not request a password reset, no further action is required.'
            }
        },
        'es': {
            'magic_link': {
                'subject': 'Tu enlace mágico para Nexando.ai',
                'title': '¡Hola de nuevo!',
                'message_body': 'Haz clic en el botón de abajo para acceder de forma segura a tu cuenta. Sin contraseñas.',
                'cta_text': 'Entrar a Nexando',
                'disclaimer': 'Este enlace es válido por 10 minutos. Si no solicitaste esto, puedes ignorar este correo.'
            },
            'password_reset': {
                'subject': 'Restablece tu contraseña de Nexando',
                'title': 'Restablecer Contraseña',
                'message_body': 'Recibimos una solicitud para restablecer tu contraseña. Haz clic abajo para elegir una nueva.',
                'cta_text': 'Restablecer Contraseña',
                'disclaimer': 'Si no solicitaste restablecer tu contraseña, no es necesario realizar ninguna acción.'
            }
        }
    }
    
    selected_lang = lang if lang in translations else 'en'
    content = translations[selected_lang][link_type]
    content['link'] = link_url
    return content


def send_aesthetic_email(to_email, lang, link_type, link_url):
    """
    Renderiza la plantilla HTML y envía el correo con diseño.
    """
    content_data = get_email_content(lang, link_type, link_url)
    html_content = render_to_string('emails/magic_link.html', content_data)
    
    send_email_via_sendgrid(
        to_email=to_email,
        subject=content_data['subject'],
        html_content=html_content
    )


def send_magic_link_email(user, lang='en'):
    """
    Genera el token y dispara el correo estético de Magic Link.
    """
    token = AccessToken.for_user(user)
    token.set_exp(lifetime=timedelta(minutes=10))
    base_url = os.environ.get('FRONTEND_URL', "http://localhost:3000")
    magic_link_url = f"{base_url}/auth/magic-link/verify/?token={str(token)}"
    
    send_aesthetic_email(user.email, lang, 'magic_link', magic_link_url)


"""
BLOQUE: VISTAS DE AUTENTICACIÓN (HÍBRIDA & SOCIAL)
"""

class SignupView(generics.CreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = SignupSerializer
    throttle_scope = 'auth'

    def create(self, request, *args, **kwargs):
        email = request.data.get('email')
        try:
            validate_email(email)
        except DjangoValidationError:
            return Response({'error': 'Invalid email format'}, status=400)

        if User.objects.filter(username=email).exists():
             return Response({'error': 'Email registered. Please login.'}, status=409)
        
        try:
            return super().create(request, *args, **kwargs)
        except Exception as e:
            logger.error("Signup error", exc_info=True)
            return Response({'error': 'Registration failed.'}, status=500)


class ValidateEmailView(APIView):
    permission_classes = [AllowAny]
    throttle_scope = 'auth'

    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        if not email: return Response({'error': 'Email required'}, status=400)
        try:
            validate_email(email)
        except DjangoValidationError:
            return Response({'error': 'Invalid email format'}, status=400)
        if User.objects.filter(username=email).exists():
            return Response({'error': 'Email registered'}, status=409)
        return Response(status=204)


class RegisterView(APIView):
    permission_classes = [AllowAny]
    throttle_scope = 'auth'

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        user_lang = request.META.get('HTTP_ACCEPT_LANGUAGE', 'en')[:2]
        email = request.data.get('email')
        first_name = request.data.get('first_name')
        interests_data = request.data.get('interests', [])
        
        if not email or not first_name or not first_name.strip():
            return Response({'error': 'Email and name required'}, status=400)
        
        try:
            validate_email(email)
        except DjangoValidationError:
            return Response({'error': 'Invalid email format'}, status=400)
        
        try:
            user = User.objects.create_user(username=email, email=email, is_active=False)
            profile = Profile.objects.create(user=user, first_name=first_name.strip())
            
            seen_interests = set()
            for item in interests_data:
                name = item.get('name', '').strip().title() if isinstance(item, dict) else str(item).strip().title()
                if name and name not in seen_interests:
                    seen_interests.add(name)
                    interest_obj, _ = Interest.objects.get_or_create(name=name)
                    UserInterest.objects.create(profile=profile, interest=interest_obj, is_primary=item.get('is_primary', False) if isinstance(item, dict) else False)
            
            send_magic_link_email(user, lang=user_lang)
            return Response({'detail': 'Magic link sent.'}, status=201)
        except Exception as e:
            logger.error("RegisterView Error", exc_info=True)
            return Response({'error': 'Service unavailable'}, status=502)


class LoginView(APIView):
    permission_classes = [AllowAny]
    throttle_scope = 'auth'

    def post(self, request, *args, **kwargs):
        user_lang = request.META.get('HTTP_ACCEPT_LANGUAGE', 'en')[:2]
        email = request.data.get('email')
        if not email: return Response({'error': 'Email required'}, status=400)
        try:
            user = User.objects.get(username=email)
            send_magic_link_email(user, lang=user_lang)
        except User.DoesNotExist:
            pass
        return Response({'detail': 'If an account exists, a link has been sent.'}, status=200)


class SetPasswordView(APIView):
    permission_classes = [AllowAny]
    throttle_scope = 'auth'

    def post(self, request, *args, **kwargs):
        token_str = request.data.get('token')
        password = request.data.get('password')
        if not token_str or not password: return Response({'error': 'Data required'}, status=400)
        try:
            token = AccessToken(token_str); token.verify()
            user = User.objects.get(id=token['user_id'])
            user.set_password(password); user.is_active = True; user.save()
            Profile.objects.get_or_create(user=user, defaults={'first_name': user.first_name or 'User'})
            tokens = RefreshToken.for_user(user)
            return Response({'refresh': str(tokens), 'access': str(tokens.access_token)}, status=200)
        except (TokenError, InvalidToken): return Response({'error': 'Invalid token'}, status=401)
        except Exception as e:
            logger.error("SetPassword Error", exc_info=True)
            return Response({'error': 'Processing error'}, status=500)


class GoogleLoginView(APIView):
    permission_classes = [AllowAny]
    throttle_scope = 'auth'

    def post(self, request):
        serializer = GoogleLoginSerializer(data=request.data)
        if not serializer.is_valid(): return Response(serializer.errors, status=400)
        token = serializer.validated_data['token']
        GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
        try:
            idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), GOOGLE_CLIENT_ID)
            email = idinfo['email']; first_name = idinfo.get('given_name', 'User')
            with transaction.atomic():
                user = User.objects.filter(email=email).first()
                created = False
                if not user:
                    user = User.objects.create_user(username=email, email=email, is_active=True, first_name=first_name)
                    created = True
                Profile.objects.get_or_create(user=user, defaults={'first_name': first_name})
            refresh = RefreshToken.for_user(user)
            return Response({'refresh': str(refresh), 'access': str(refresh.access_token), 'is_new_user': created}, status=200)
        except ValueError: return Response({'error': 'Invalid Google Token'}, status=400)
        except Exception as e:
            logger.error(f"Google Login Error: {e}", exc_info=True)
            return Response({'error': 'Authentication failed'}, status=500)


"""
BLOQUE: RECUPERACIÓN DE CONTRASEÑA
"""

class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]
    throttle_scope = 'auth'

    def post(self, request):
        user_lang = request.META.get('HTTP_ACCEPT_LANGUAGE', 'en')[:2]
        serializer = PasswordResetRequestSerializer(data=request.data)
        if not serializer.is_valid(): return Response(serializer.errors, status=400)
        email = serializer.validated_data['email']
        try:
            user = User.objects.get(email=email)
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            base_url = os.environ.get('FRONTEND_URL', "http://localhost:3000")
            reset_link = f"{base_url}/auth/reset-password?uid={uid}&token={token}"
            send_aesthetic_email(email, user_lang, 'password_reset', reset_link)
        except User.DoesNotExist: pass 
        return Response({'detail': 'If the email exists, a reset link has been sent.'}, status=200)


class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]
    throttle_scope = 'auth'

    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if not serializer.is_valid(): return Response(serializer.errors, status=400)
        uid = serializer.validated_data['uid']; token = serializer.validated_data['token']; password = serializer.validated_data['new_password']
        try:
            user_id = force_str(urlsafe_base64_decode(uid)); user = User.objects.get(pk=user_id)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist): return Response({'error': 'Invalid link'}, status=400)
        if not default_token_generator.check_token(user, token): return Response({'error': 'Invalid or expired token'}, status=400)
        user.set_password(password); user.save()
        return Response({'detail': 'Password reset successful.'}, status=200)


"""
BLOQUE: GESTIÓN DE PERFIL
"""

class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        profile, _ = Profile.objects.get_or_create(user=request.user, defaults={'first_name': request.user.first_name or 'User'})
        return Response(ProfileSerializer(profile).data)
    
    def patch(self, request, format=None):
        profile, _ = Profile.objects.get_or_create(user=request.user)
        serializer = ProfileSerializer(profile, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save(); cache.delete(f"user_{request.user.id}_interests") 
            return Response(serializer.data)
        return Response(serializer.errors, status=400)


class ProfilePictureUploadView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)
    throttle_scope = 'uploads'

    def put(self, request, format=None):
        if 'profile_picture' not in request.FILES: return Response({'error': 'No file'}, status=400)
        file_obj = request.FILES['profile_picture']
        if file_obj.size > MAX_PROFILE_PICTURE_SIZE: return Response({'error': 'File too large'}, status=400)
        if file_obj.name.split('.')[-1].lower() not in ['jpg', 'jpeg', 'png', 'webp']: return Response({'error': 'Invalid type'}, status=400)
        profile = request.user.profile
        try:
            img = Image.open(file_obj); img.verify(); file_obj.seek(0); img = Image.open(file_obj)
            if img.width * img.height > MAX_IMAGE_PIXELS: return Response({'error': 'Dimensions too large'}, status=400)
            buffer = BytesIO(); img.save(buffer, format='WEBP', quality=85); buffer.seek(0)
            filename = f'{profile.user.id}_{os.path.splitext(file_obj.name)[0]}.webp'
            profile.profile_picture_url.save(filename, ContentFile(buffer.read()), save=True)
            return Response(ProfilePictureSerializer(profile).data)
        except Exception: logger.error("Upload Error", exc_info=True); return Response({'error': 'Failed'}, status=500)


class ProfileDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, user_id, format=None):
        target = get_object_or_404(User, pk=user_id); req = request.user
        if req.id == target.id: return Response(ProfileSerializer(target.profile).data)
        u1, u2 = sorted([req.id, target.id])
        if Connection.objects.filter(user1_id=u1, user2_id=u2).exists() or MatchAction.objects.filter(actor=target, target=req, action='like').exists():
            return Response(ProfileSerializer(target.profile).data)
        return Response({'detail': 'Not found'}, status=404)


"""
BLOQUE: MATCHING Y CONEXIONES
"""

class RecommendationView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ProfileSerializer

    def get_queryset(self):
        user = self.request.user; cache_key = f"user_{user.id}_interests"; my_ids = cache.get(cache_key)
        if not my_ids:
            my_ids = list(user.profile.userinterest_set.values_list('interest_id', flat=True))
            cache.set(cache_key, my_ids, timeout=60)
        interacted = list(MatchAction.objects.filter(actor=user).values_list('target_id', flat=True))
        queryset = Profile.objects.filter(interests__id__in=my_ids).exclude(user=user).exclude(user_id__in=interacted).distinct()
        return queryset.annotate(c=Count('interests', filter=Q(interests__id__in=my_ids))).order_by('-c', '?')


class MatchActionView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_scope = 'messages'

    def post(self, request, *args, **kwargs):
        actor = request.user; target_id = request.data.get('target_id'); action = request.data.get('action')
        if not target_id or action not in ['like', 'pass']: return Response({'error': 'Invalid data'}, status=400)
        with transaction.atomic():
            try: target = User.objects.select_for_update().get(id=target_id)
            except User.DoesNotExist: return Response({'error': 'Not found'}, status=404)
            if actor.id == target.id: return Response({'error': 'Self action prohibited'}, status=400)
            MatchAction.objects.update_or_create(actor=actor, target=target, defaults={'action': action})
            if action == 'like' and MatchAction.objects.filter(actor=target, target=actor, action='like').exists():
                u1, u2 = sorted([actor.id, target.id])
                try: conn, cr = Connection.objects.get_or_create(user1_id=u1, user2_id=u2)
                except IntegrityError: conn = Connection.objects.get(user1_id=u1, user2_id=u2); cr = False
                if cr: send_match_notification_async(actor, target)
                return Response({'status': 'match', 'connection_id': conn.id}, status=201)
        return Response({'status': action}, status=200)


class ConnectionListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ProfileSerializer

    def get_queryset(self):
        user = self.request.user; conns = Connection.objects.filter(Q(user1=user) | Q(user2=user))
        p_ids = [c.user2_id if c.user1_id == user.id else c.user1_id for c in conns]
        return Profile.objects.filter(user__id__in=p_ids).select_related('user')


"""
BLOQUE: MENSAJERÍA (CHAT)
"""

class SendMessageView(generics.CreateAPIView):
    permission_classes = [IsAuthenticated]; serializer_class = MessageSerializer; throttle_scope = 'messages'

    def perform_create(self, serializer):
        recipient = serializer.validated_data['recipient']; u1, u2 = sorted([self.request.user.id, recipient.id])
        if not Connection.objects.filter(user1_id=u1, user2_id=u2).exists(): raise PermissionDenied("Not connected")
        serializer.save(sender=self.request.user)


class ConversationView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]; serializer_class = MessageSerializer

    def get_queryset(self):
        user = self.request.user; other_id = self.kwargs['user_id']; u1, u2 = sorted([user.id, other_id])
        if not Connection.objects.filter(user1_id=u1, user2_id=u2).exists(): raise PermissionDenied("Access denied")
        return Message.objects.filter(Q(sender=user, recipient_id=other_id) | Q(sender_id=other_id, recipient=user)).order_by('timestamp')


"""
BLOQUE: INTELIGENCIA ARTIFICIAL Y COMUNIDAD
"""

class AIChatView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_scope = 'messages'

    def post(self, request):
        serializer = AIChatSerializer(data=request.data)
        if not serializer.is_valid(): return Response(serializer.errors, status=400)
        user_message = serializer.validated_data['message']; history = serializer.validated_data['history']; api_key = os.environ.get('OPENAI_API_KEY')
        if not api_key: return Response({'error': 'AI Service configuration missing'}, status=503)
        try:
            client = openai.OpenAI(api_key=api_key)
            messages_payload = [{"role": "system", "content": "Eres NexandoBot, un asistente útil para jóvenes profesionales."}]
            for msg in history[-4:]:
                if 'role' in msg and 'content' in msg: messages_payload.append(msg)
            messages_payload.append({"role": "user", "content": user_message})
            completion = client.chat.completions.create(model="gpt-5-nano", messages=messages_payload, max_tokens=300)
            return Response({'reply': completion.choices[0].message.content}, status=200)
        except Exception as e:
            logger.error(f"OpenAI API Error: {str(e)}")
            return Response({'error': 'AI service unavailable'}, status=502)


class FeedbackView(generics.CreateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = FeedbackSerializer
    throttle_scope = 'uploads'

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)
        admin_email = os.environ.get('DEFAULT_FROM_EMAIL') 
        if admin_email:
            subject = f"New Feedback: {self.request.user.username}"
            send_email_via_sendgrid(admin_email, subject, serializer.validated_data['content'])