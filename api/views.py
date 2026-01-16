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
from django.db.models import Count, Q, F
from django.contrib.auth.models import User
from django.conf import settings
from django.core.validators import validate_email
from django.core.exceptions import ValidationError, PermissionDenied

# DRF Imports
from rest_framework import generics, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle, ScopedRateThrottle
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken

# Third Party
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

# Local Imports
from .models import Profile, Interest, UserInterest, MatchAction, Connection, Message
from .serializers import (
    ProfileSerializer, 
    SignupSerializer, 
    ProfilePictureSerializer,
    MessageSerializer
)

logger = logging.getLogger(__name__)

# --- CONSTANTES ---
MAX_PROFILE_PICTURE_SIZE = 5 * 1024 * 1024 # 5MB
MAX_IMAGE_PIXELS = 4096 * 4096 # 16 MP Limit

# --- UTILIDADES ---

def send_match_notification_async(user1, user2):
    # TODO: Mover a Celery
    logger.info(f"Match event triggered: {user1.username} <-> {user2.username}")

def send_magic_link_email(user):
    api_key = settings.SENDGRID_API_KEY
    from_email = settings.DEFAULT_FROM_EMAIL
    
    if not api_key or not from_email:
        logger.critical("Email configuration missing.")
        raise ValueError("Server configuration error.")
    
    token = AccessToken.for_user(user)
    token.set_exp(lifetime=timedelta(minutes=10))
    
    # ALTA-04: URL Dinámica
    base_url = os.environ.get('FRONTEND_URL', "http://localhost:3000")
    magic_link_url = f"{base_url}/auth/magic-link/verify/?token={str(token)}"
    
    message = Mail(
        from_email=from_email,
        to_emails=user.email,
        subject='Your Magic Link to Nexando.ai',
        html_content=f'<strong>Welcome!</strong><br>Click <a href="{magic_link_url}">here</a>. Valid for 10 minutes.'
    )
    
    try:
        sg = SendGridAPIClient(api_key)
        response = sg.send(message)
        if response.status_code not in [200, 201, 202]:
            logger.error(f"SendGrid Error {response.status_code}")
            raise Exception("Email provider rejected request")
    except Exception as e:
        logger.error("Failed to send email", exc_info=True)
        raise

# --- VISTAS DE AUTENTICACIÓN ---

class SignupView(generics.CreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = SignupSerializer
    throttle_scope = 'auth' # MEDIO-01

    def create(self, request, *args, **kwargs):
        email = request.data.get('email')
        
        # ALTA-08: Validación de formato
        try:
            validate_email(email)
        except ValidationError:
            return Response({'error': 'Invalid email format'}, status=400)

        if User.objects.filter(username=email).exists():
             return Response(
                {'error': 'This email is already registered. Please login.'}, 
                status=status.HTTP_409_CONFLICT
            )
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
        except ValidationError:
            return Response({'error': 'Invalid email format'}, status=400)

        if User.objects.filter(username=email).exists():
            return Response({'error': 'Email registered'}, status=409)
        return Response(status=204)

class RegisterView(APIView):
    permission_classes = [AllowAny]
    throttle_scope = 'auth'

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        first_name = request.data.get('first_name')
        interests_data = request.data.get('interests', [])
        
        # BUG-04: Sanitización de nombre
        if not email or not first_name or not first_name.strip(): 
            return Response({'error': 'Data required'}, status=400)
        
        first_name = first_name.strip()
        
        try:
            validate_email(email)
        except ValidationError:
            return Response({'error': 'Invalid email format'}, status=400)
        
        try:
            user = User.objects.create_user(username=email, email=email, is_active=False)
            profile = Profile.objects.create(user=user, first_name=first_name)
            
            # Lógica de intereses segura
            seen_interests = set()
            for item in interests_data:
                name = item.get('name', '').strip().title() if isinstance(item, dict) else str(item).strip().title()
                if name and name not in seen_interests:
                    seen_interests.add(name)
                    interest_obj, _ = Interest.objects.get_or_create(name=name)
                    is_primary = item.get('is_primary', False) if isinstance(item, dict) else False
                    UserInterest.objects.create(profile=profile, interest=interest_obj, is_primary=is_primary)
            
            send_magic_link_email(user)
            return Response({'detail': 'Magic link sent'}, status=201)
        except Exception as e:
            logger.error("RegisterView Error", exc_info=True)
            return Response({'error': 'Service unavailable'}, status=502)

class LoginView(APIView):
    permission_classes = [AllowAny]
    throttle_scope = 'auth'

    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        if not email: return Response({'error': 'Email required'}, status=400)
        
        try:
            validate_email(email)
        except ValidationError:
            # BUG-03: Validación consistente, pero sin revelar error para evitar enumeration
            return Response({'detail': 'Link sent if exists'}, status=200)

        try:
            user = User.objects.get(username=email)
            send_magic_link_email(user)
            return Response({'detail': 'Link sent if exists'}, status=200)
        except User.DoesNotExist:
            return Response({'detail': 'Link sent if exists'}, status=200)
        except Exception as e:
            logger.error("LoginView Error", exc_info=True)
            return Response({'error': 'Service error'}, status=502)

class SetPasswordView(APIView):
    permission_classes = [AllowAny]
    throttle_scope = 'auth'

    def post(self, request, *args, **kwargs):
        token_str = request.data.get('token')
        password = request.data.get('password')
        if not token_str or not password: return Response({'error': 'Data required'}, status=400)
        try:
            token = AccessToken(token_str)
            token.verify()
            
            user = User.objects.get(id=token['user_id'])
            user.set_password(password)
            user.is_active = True
            user.save()
            
            tokens = RefreshToken.for_user(user)
            return Response({'refresh': str(tokens), 'access': str(tokens.access_token)}, status=200)
        except (TokenError, InvalidToken):
            return Response({'error': 'Invalid or expired token'}, status=401)
        except Exception as e:
            logger.error("SetPassword Error", exc_info=True)
            return Response({'error': 'Processing error'}, status=500)

# --- VISTAS DE PERFIL ---

class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, format=None):
        serializer = ProfileSerializer(request.user.profile)
        return Response(serializer.data)
    
    def patch(self, request, format=None):
        serializer = ProfileSerializer(request.user.profile, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            cache.delete(f"user_{request.user.id}_interests") 
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

class ProfilePictureUploadView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)
    throttle_scope = 'uploads'
    
    def put(self, request, format=None):
        if 'profile_picture' not in request.FILES: return Response({'error': 'No file'}, status=400)
        file_obj = request.FILES['profile_picture']
        
        if file_obj.size > MAX_PROFILE_PICTURE_SIZE:
            return Response({'error': 'File too large (max 5MB)'}, status=400)
            
        allowed_extensions = ['jpg', 'jpeg', 'png', 'webp']
        ext = file_obj.name.split('.')[-1].lower()
        if ext not in allowed_extensions:
            return Response({'error': 'Invalid file type'}, status=400)

        profile = request.user.profile
        try:
            # ALTO-02: Pixel Flood Protection
            img = Image.open(file_obj)
            img.verify()
            
            file_obj.seek(0)
            img = Image.open(file_obj)
            
            if img.width * img.height > MAX_IMAGE_PIXELS:
                return Response({'error': 'Image dimensions too large'}, status=400)

            buffer = BytesIO()
            img.save(buffer, format='WEBP', quality=85)
            buffer.seek(0)
            
            filename = f'{profile.user.id}_{os.path.splitext(file_obj.name)[0]}.webp'
            profile.profile_picture_url.save(filename, ContentFile(buffer.read()), save=True)
            
            serializer = ProfileSerializer(profile)
            return Response(serializer.data)
        except Exception as e:
            logger.error("Image Upload Error", exc_info=True)
            return Response({'error': 'Failed to process image'}, status=500)

class ProfileDetailView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request, user_id, format=None):
        # CRÍTICO-02: Prevenir enumeración/scraping masivo
        target_user = get_object_or_404(User, pk=user_id)
        requester = request.user
        
        # Permitir si es el mismo usuario
        if requester.id == target_user.id:
            profile = get_object_or_404(Profile, pk=user_id)
            return Response(ProfileSerializer(profile).data)

        # Permitir si están conectados
        user1_id, user2_id = sorted([requester.id, target_user.id])
        is_connected = Connection.objects.filter(user1_id=user1_id, user2_id=user2_id).exists()
        
        # Permitir si es una recomendación válida (implícito por el algoritmo de match)
        # Opcional: Verificar caché de recomendaciones si queremos ser estrictos
        
        if is_connected:
            profile = get_object_or_404(Profile, pk=user_id)
            return Response(ProfileSerializer(profile).data)
        
        # Si no están conectados, verificamos si hay una "MatchAction" pendiente (alguien que me dio like)
        # Esto permite ver el perfil antes de aceptar.
        has_interaction = MatchAction.objects.filter(actor=target_user, target=requester).exists()
        
        if has_interaction:
             profile = get_object_or_404(Profile, pk=user_id)
             return Response(ProfileSerializer(profile).data)

        # Si llegamos aquí, es un acceso no autorizado a un perfil ajeno
        # Para evitar enumeración, devolvemos 404 en lugar de 403
        return Response({'detail': 'Not found'}, status=404)

# --- VISTAS DE MATCHING ---

class RecommendationView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ProfileSerializer

    def get_queryset(self):
        user = self.request.user
        cache_key = f"user_{user.id}_interests"
        my_interest_ids = cache.get(cache_key)
        
        if not my_interest_ids:
            my_interest_ids = list(user.profile.userinterest_set.values_list('interest_id', flat=True))
            cache.set(cache_key, my_interest_ids, timeout=60)

        interacted_ids = list(MatchAction.objects.filter(actor=user).values_list('target_id', flat=True))
        
        queryset = Profile.objects.filter(
            interests__id__in=my_interest_ids
        ).exclude(
            user=user
        ).exclude(
            user_id__in=interacted_ids
        ).distinct()
        
        return queryset.annotate(
            common_count=Count('interests', filter=Q(interests__id__in=my_interest_ids))
        ).order_by('-common_count', '?')

class MatchActionView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_scope = 'messages' # Reusing rate limit
    
    def post(self, request, *args, **kwargs):
        actor = request.user
        target_id = request.data.get('target_id')
        action = request.data.get('action')

        if not target_id or action not in ['like', 'pass']: 
            return Response({'error': 'Invalid data'}, status=400)
        
        # BUG-05 & BUG-02 Fixes
        with transaction.atomic():
            try:
                target = User.objects.select_for_update().get(id=target_id)
            except User.DoesNotExist: return Response({'error': 'Not found'}, status=404)
            
            if actor.id == target.id: return Response({'error': 'Self action'}, status=400)

            MatchAction.objects.update_or_create(actor=actor, target=target, defaults={'action': action})
            
            if action == 'like':
                is_match = MatchAction.objects.filter(actor=target, target=actor, action='like').exists()
                if is_match:
                    user1_id, user2_id = sorted([actor.id, target.id])
                    try:
                        conn, created = Connection.objects.get_or_create(user1_id=user1_id, user2_id=user2_id)
                        if created:
                            send_match_notification_async(actor, target)
                    except IntegrityError:
                        conn = Connection.objects.get(user1_id=user1_id, user2_id=user2_id)
                    
                    return Response({'status': 'match', 'connection_id': conn.id}, status=201)

        return Response({'status': action}, status=200)

class ConnectionListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ProfileSerializer

    def get_queryset(self):
        user = self.request.user
        connections = Connection.objects.filter(Q(user1=user) | Q(user2=user))
        partner_ids = [conn.user2_id if conn.user1_id == user.id else conn.user1_id for conn in connections]
        return Profile.objects.filter(user__id__in=partner_ids).select_related('user')

# --- CHAT ---

class SendMessageView(generics.CreateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = MessageSerializer
    throttle_scope = 'messages'

    def perform_create(self, serializer):
        recipient_id = self.request.data.get('recipient_id')
        recipient = get_object_or_404(User, pk=recipient_id)
        
        # CRÍTICO-01: Verify connection exists
        user1_id, user2_id = sorted([self.request.user.id, recipient.id])
        if not Connection.objects.filter(user1_id=user1_id, user2_id=user2_id).exists():
            raise PermissionDenied("You can only message users you have matched with.")
            
        serializer.save(sender=self.request.user, recipient=recipient)

class ConversationView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = MessageSerializer

    def get_queryset(self):
        user = self.request.user
        other_user_id = self.kwargs['user_id']
        
        # CRÍTICO-01 (Lectura): Verificar que somos parte de esta conversación
        # Simplemente verificar si somos el sender o recipient en la query ya lo hace,
        # pero es mejor verificar la conexión primero por seguridad.
        user1_id, user2_id = sorted([user.id, other_user_id])
        if not Connection.objects.filter(user1_id=user1_id, user2_id=user2_id).exists():
             raise PermissionDenied("Access denied to conversation.")

        return Message.objects.filter(
            Q(sender=user, recipient_id=other_user_id) | 
            Q(sender_id=other_user_id, recipient=user)
        ).order_by('timestamp')