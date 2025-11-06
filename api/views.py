# api/views.py

import os
from io import BytesIO
from PIL import Image
from datetime import timedelta

# Imports de Django
from django.core.files.base import ContentFile
from django.shortcuts import get_object_or_404
from django.db import IntegrityError
from django.contrib.auth.models import User
from django.conf import settings

# Imports de Django Rest Framework
from rest_framework import generics, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken

# Imports de Terceros
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

# Imports locales
from .models import Profile, Interest 
from .serializers import ProfileSerializer, UserCreateSerializer, ProfilePictureSerializer


# --- VISTAS DE AUTENTICACIÓN ---

class RequestMagicLinkView(APIView):
    """
    Vista para solicitar un "magic link".
    Utiliza una lógica robusta de "update_or_create" para el Perfil.
    """
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        api_key = settings.SENDGRID_API_KEY
        from_email = settings.DEFAULT_FROM_EMAIL

        if not api_key or not from_email:
            return Response(
                {'error': 'Server configuration error: Email service is not configured.'}, 
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )

        email = request.data.get('email')
        first_name = request.data.get('first_name')
        interests_data = request.data.get('interests', [])

        if not email or not first_name:
            return Response({'error': 'Email and first_name are required.'}, status=status.HTTP_400_BAD_REQUEST)

        user, created = User.objects.get_or_create(
            username=email,
            defaults={'email': email, 'is_active': False}
        )
        
        profile, profile_created = Profile.objects.update_or_create(
            user=user,
            defaults={'first_name': first_name}
        )

        profile.interests.clear()
        for interest_name in interests_data:
            interest_obj, _ = Interest.objects.get_or_create(
                name=interest_name.strip().title()
            )
            profile.interests.add(interest_obj)

        token = RefreshToken.for_user(user)
        token.set_exp(lifetime=timedelta(minutes=15))
        
        magic_link_url = f"http://localhost:3000/auth/magic-link/verify/?token={str(token.access_token)}"

        message = Mail(
            from_email=from_email,
            to_emails=email,
            subject='Your Magic Link to Nexando.ai',
            html_content=f'<strong>Welcome to Nexando!</strong><br>Click <a href="{magic_link_url}">here</a> to log in. This link is valid for 15 minutes.'
        )
        try:
            sg = SendGridAPIClient(api_key)
            response = sg.send(message)
            if response.status_code >= 300:
                return Response({'error': f'Email provider rejected the request: {response.body}'}, status=status.HTTP_502_BAD_GATEWAY)
            
            return Response({'detail': 'If an account with this email exists or was created, a magic link has been sent.'}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({'error': f'An unexpected error occurred while sending the email: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
# --- NUEVA VISTA DE VERIFICACIÓN ---
        
class VerifyMagicLinkView(APIView):
    """
    Verifica un token de un solo uso (magic link) y devuelve 
    un par de tokens de sesión estándar (access y refresh).
    """
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        token_str = request.data.get('token')
        if not token_str:
            return Response({'error': 'Token is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # 1. Decodificamos y validamos el token de acceso de un solo uso.
            #    Esto verificará la firma y la fecha de expiración.
            token = AccessToken(token_str)
            token.verify()

            # 2. Extraemos el ID del usuario del token.
            user_id = token['user_id']
            user = User.objects.get(id=user_id)

            # 3. Activamos al usuario si es la primera vez que inicia sesión.
            if not user.is_active:
                user.is_active = True
                user.save()

            # 4. Generamos un par de tokens de sesión estándar y duraderos.
            session_tokens = RefreshToken.for_user(user)
            
            # 5. Devolvemos los tokens de sesión al frontend.
            return Response({
                'refresh': str(session_tokens),
                'access': str(session_tokens.access_token),
            }, status=status.HTTP_200_OK)

        except (TokenError, InvalidToken, User.DoesNotExist) as e:
            # Si el token es inválido, expirado, o el usuario no existe, devolvemos un error.
            return Response({'error': 'Invalid or expired magic link.'}, status=status.HTTP_401_UNAUTHORIZED)

# --- VISTAS DE PERFIL Y USUARIO ---

class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, format=None):
        serializer = ProfileSerializer(request.user.profile)
        return Response(serializer.data, status=status.HTTP_200_OK)
    def patch(self, request, format=None):
        profile = request.user.profile
        serializer = ProfileSerializer(profile, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ProfilePictureUploadView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)
    def put(self, request, format=None):
        if 'profile_picture' not in request.FILES:
            return Response({'error': 'No file was submitted.'}, status=status.HTTP_400_BAD_REQUEST)
        file_obj = request.FILES['profile_picture']
        profile = request.user.profile
        try:
            img = Image.open(file_obj)
            buffer = BytesIO()
            img.save(buffer, format='WEBP', quality=85)
            buffer.seek(0)
            webp_filename = f'{profile.user.id}_{os.path.splitext(file_obj.name)[0]}.webp'
            profile.profile_picture_url.save(webp_filename, ContentFile(buffer.read()), save=True)
            serializer = ProfileSerializer(profile)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': f'Image processing failed: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ProfileDetailView(APIView):
    def get(self, request, user_id, format=None):
        profile = get_object_or_404(Profile, pk=user_id)
        serializer = ProfileSerializer(profile)
        return Response(serializer.data, status=status.HTTP_200_OK)

class ProfileCreateView(generics.CreateAPIView):
    serializer_class = UserCreateSerializer
    def create(self, request, *args, **kwargs):
        try:
            return super().create(request, *args, **kwargs)
        except IntegrityError:
            error_data = {'email': ['A user with that email already exists.']}
            return Response(error_data, status=status.HTTP_400_BAD_REQUEST)


# --- VISTA DE MATCHING ---

class FirstMatchView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, format=None):
        user_profile = request.user.profile
        user_interests = user_profile.interests.all()
        if not user_interests.exists():
            return Response({'detail': 'User has no interests to match with.'}, status=status.HTTP_404_NOT_FOUND)
        potential_matches = Profile.objects.exclude(user=request.user).filter(interests__in=user_interests).distinct().first()
        if potential_matches:
            serializer = ProfileSerializer(potential_matches)
            return Response(serializer.data)
        else:
            return Response({'detail': 'No matches found at this time.'}, status=status.HTTP_404_NOT_FOUND)