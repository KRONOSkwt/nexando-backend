import os
from io import BytesIO
from PIL import Image
from datetime import timedelta

from django.core.files.base import ContentFile
from django.core.cache import cache
from django.shortcuts import get_object_or_404
from django.db import IntegrityError, transaction
from django.db.models import Count, Q, F
from django.contrib.auth.models import User
from django.conf import settings

from rest_framework import generics, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken

from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

from .models import Profile, Interest, UserInterest, MatchAction, Connection
from .serializers import ProfileSerializer, SignupSerializer, ProfilePictureSerializer

"""
UTILIDADES
"""

def send_match_notification_async(user1, user2):
    # Placeholder para Celery
    print(f"--- [NOTIFICATION] Match entre {user1.username} y {user2.username} ---")

def send_magic_link_email(user):
    api_key = settings.SENDGRID_API_KEY
    from_email = settings.DEFAULT_FROM_EMAIL
    if not api_key or not from_email:
        raise ValueError("Server configuration error: Email service is not configured.")
    
    token = RefreshToken.for_user(user)
    token.set_exp(lifetime=timedelta(minutes=15))
    magic_link_url = f"http://localhost:3000/auth/magic-link/verify/?token={str(token.access_token)}"
    
    message = Mail(
        from_email=from_email,
        to_emails=user.email,
        subject='Your Magic Link to Nexando.ai',
        html_content=f'<strong>Welcome to Nexando!</strong><br>Click <a href="{magic_link_url}">here</a> to continue.'
    )
    sg = SendGridAPIClient(api_key)
    response = sg.send(message)
    if response.status_code != 202:
        raise Exception(f"Email provider rejected request: {response.body}")

"""
VISTAS DE AUTENTICACIÓN (HÍBRIDA)
"""

class SignupView(generics.CreateAPIView):
    """
    Registro Clásico: Email + Password. Retorna Tokens.
    """
    permission_classes = [AllowAny]
    serializer_class = SignupSerializer

    def create(self, request, *args, **kwargs):
        email = request.data.get('email')
        if User.objects.filter(username=email).exists():
             return Response(
                {'error': 'This email is already registered. Please login.'}, 
                status=status.HTTP_409_CONFLICT
            )
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

class ValidateEmailView(APIView):
    permission_classes = [AllowAny]
    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        if not email: return Response({'error': 'Email required'}, status=400)
        if User.objects.filter(username=email).exists():
            return Response({'error': 'Email registered'}, status=409)
        return Response(status=204)

class RegisterView(APIView):
    """
    Registro Passwordless (Magic Link).
    """
    permission_classes = [AllowAny]
    @transaction.atomic
    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        first_name = request.data.get('first_name')
        interests_data = request.data.get('interests', [])
        
        if not email or not first_name: return Response({'error': 'Data required'}, status=400)
        
        try:
            user = User.objects.create_user(username=email, email=email, is_active=False)
            profile = Profile.objects.create(user=user, first_name=first_name)
            
            for item in interests_data:
                if isinstance(item, dict):
                    name = item.get('name', '').strip().title()
                    is_primary = item.get('is_primary', False)
                else:
                    name = str(item).strip().title()
                    is_primary = False
                
                if name:
                    interest_obj, _ = Interest.objects.get_or_create(name=name)
                    UserInterest.objects.create(profile=profile, interest=interest_obj, is_primary=is_primary)
            
            send_magic_link_email(user)
            return Response({'detail': 'Magic link sent'}, status=201)
        except Exception as e:
            return Response({'error': str(e)}, status=502)

class LoginView(APIView):
    permission_classes = [AllowAny]
    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        if not email: return Response({'error': 'Email required'}, status=400)
        try:
            user = User.objects.get(username=email)
            send_magic_link_email(user)
            return Response({'detail': 'Link sent if exists'}, status=200)
        except User.DoesNotExist:
            return Response({'detail': 'Link sent if exists'}, status=200)
        except Exception as e:
            return Response({'error': str(e)}, status=502)

class SetPasswordView(APIView):
    permission_classes = [AllowAny]
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
        except Exception:
            return Response({'error': 'Invalid token'}, status=401)

"""
VISTAS DE PERFIL
"""

class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, format=None):
        serializer = ProfileSerializer(request.user.profile)
        return Response(serializer.data)
    
    def patch(self, request, format=None):
        serializer = ProfileSerializer(request.user.profile, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            # Invalidar caché de recomendaciones
            cache.delete_many([
                f"user_{request.user.id}_recommendations_primary",
                f"user_{request.user.id}_recommendations_secondary"
            ])
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

class ProfilePictureUploadView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)
    def put(self, request, format=None):
        if 'profile_picture' not in request.FILES: return Response({'error': 'No file'}, status=400)
        file_obj = request.FILES['profile_picture']
        profile = request.user.profile
        try:
            # Optimización WebP
            img = Image.open(file_obj)
            buffer = BytesIO()
            img.save(buffer, format='WEBP', quality=85)
            buffer.seek(0)
            filename = f'{profile.user.id}_{os.path.splitext(file_obj.name)[0]}.webp'
            profile.profile_picture_url.save(filename, ContentFile(buffer.read()), save=True)
            serializer = ProfileSerializer(profile)
            return Response(serializer.data)
        except Exception as e:
            return Response({'error': str(e)}, status=500)

class ProfileDetailView(APIView):
    def get(self, request, user_id, format=None):
        profile = get_object_or_404(Profile, pk=user_id)
        serializer = ProfileSerializer(profile)
        return Response(serializer.data)

"""
VISTAS DE MATCHING
"""

class RecommendationView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ProfileSerializer

    def get_queryset(self):
        user = self.request.user
        cache_key_prefix = f"user_{user.id}_recommendations"
        
        # Intentar obtener filtros de caché
        primary_ids = cache.get(f"{cache_key_prefix}_primary")
        secondary_ids = cache.get(f"{cache_key_prefix}_secondary")
        interacted_ids = cache.get(f"{cache_key_prefix}_interacted")

        if None in [primary_ids, secondary_ids, interacted_ids]:
            primary_ids = list(user.profile.userinterest_set.filter(is_primary=True).values_list('interest_id', flat=True))
            secondary_ids = list(user.profile.userinterest_set.filter(is_primary=False).values_list('interest_id', flat=True))
            interacted_ids = list(MatchAction.objects.filter(actor=user).values_list('target_id', flat=True))
            
            cache.set(f"{cache_key_prefix}_primary", primary_ids, timeout=300)
            cache.set(f"{cache_key_prefix}_secondary", secondary_ids, timeout=300)
            cache.set(f"{cache_key_prefix}_interacted", interacted_ids, timeout=300)

        # Algoritmo de Puntuación
        return Profile.objects.annotate(
            primary_score=Count('interests', filter=Q(interests__id__in=primary_ids)),
            secondary_score=Count('interests', filter=Q(interests__id__in=secondary_ids))
        ).annotate(
            total_score=F('primary_score') * 2 + F('secondary_score')
        ).exclude(
            user=user
        ).exclude(
            user_id__in=interacted_ids
        ).filter(
            total_score__gt=0
        ).order_by('-total_score', '?')

class MatchActionView(APIView):
    permission_classes = [IsAuthenticated]
    @transaction.atomic
    def post(self, request, *args, **kwargs):
        actor = request.user
        target_id = request.data.get('target_id')
        action = request.data.get('action')

        if not target_id or action not in ['like', 'pass']: return Response({'error': 'Invalid data'}, status=400)
        try:
            target = User.objects.get(id=target_id)
        except User.DoesNotExist: return Response({'error': 'Not found'}, status=404)
        
        if actor == target: return Response({'error': 'Self action'}, status=400)

        MatchAction.objects.update_or_create(actor=actor, target=target, defaults={'action': action})
        
        # Invalidar caché de interacción
        cache.delete(f"user_{actor.id}_recommendations_interacted")

        if action == 'like':
            is_match = MatchAction.objects.filter(actor=target, target=actor, action='like').exists()
            if is_match:
                user1, user2 = sorted([actor.id, target.id])
                conn, _ = Connection.objects.get_or_create(user1_id=user1, user2_id=user2)
                cache.delete(f"user_{target.id}_recommendations_interacted")
                send_match_notification_async(actor, target)
                return Response({'status': 'match', 'connection_id': conn.id}, status=201)

        return Response({'status': action}, status=200)