# api/views.py

import os
from io import BytesIO
from PIL import Image
from datetime import timedelta

# Imports de Django
from django.core.files.base import ContentFile
from django.shortcuts import get_object_or_404
from django.db import IntegrityError, transaction # <-- Importación para transacciones atómicas
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
from .serializers import ProfileSerializer

# --- FUNCIÓN AUXILIAR (sin cambios) ---
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
        html_content=f'<strong>Welcome to Nexando!</strong><br>Click <a href="{magic_link_url}">here</a> to continue. This link is valid for 15 minutes.'
    )
    sg = SendGridAPIClient(api_key)
    response = sg.send(message)
    if response.status_code != 202:
        raise Exception(f"Email provider rejected the request with status {response.status_code}: {response.body}")

# --- VISTAS DE AUTENTICACIÓN FINALES ---

class RegisterView(APIView):
    permission_classes = [AllowAny]
    @transaction.atomic # <-- ¡CLAVE! O todo tiene éxito, o todo falla.
    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        first_name = request.data.get('first_name')
        interests_data = request.data.get('interests', [])
        if not email or not first_name:
            return Response({'error': 'Email and first_name are required.'}, status=status.HTTP_400_BAD_REQUEST)
        if User.objects.filter(username=email).exists():
            return Response(
                {'error': 'This email is already registered. Please proceed to login.'}, 
                status=status.HTTP_409_CONFLICT
            )
        try:
            # Side-effect in a transaction: all DB operations are buffered
            user = User.objects.create_user(username=email, email=email, is_active=False)
            profile = Profile.objects.create(user=user, first_name=first_name)
            for interest_name in interests_data:
                interest_obj, _ = Interest.objects.get_or_create(name=interest_name.strip().title())
                profile.interests.add(interest_obj)
            
            # This is now part of the transaction. If it fails, the user is NOT created.
            send_magic_link_email(user)
            
            # If we reach here, the transaction will be committed successfully.
            return Response({'detail': 'Registration successful. A verification link has been sent to your email.'}, status=status.HTTP_201_CREATED)
        
        except Exception as e:
            # The transaction will be rolled back automatically on any exception.
            return Response({'error': f'An unexpected error occurred: {str(e)}'}, status=status.HTTP_502_BAD_GATEWAY)

class LoginView(APIView):
    permission_classes = [AllowAny]
    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        if not email: return Response({'error': 'Email is required.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(username=email)
            # La lógica de enviar el link funciona para usuarios activos e inactivos, unificando la experiencia.
            send_magic_link_email(user)
            return Response({'detail': 'If an account with that email exists, a login link has been sent.'}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'detail': 'If an account with that email exists, a login link has been sent.'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': f'An unexpected error occurred: {str(e)}'}, status=status.HTTP_502_BAD_GATEWAY)


class SetPasswordView(APIView):
    permission_classes = [AllowAny]
    def post(self, request, *args, **kwargs):
        token_str = request.data.get('token')
        password = request.data.get('password')
        if not token_str or not password: return Response({'error': 'Token and password are required.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            token = AccessToken(token_str)
            token.verify()
            user_id = token['user_id']
            user = User.objects.get(id=user_id)
            user.set_password(password)
            user.is_active = True
            user.save()
            session_tokens = RefreshToken.for_user(user)
            return Response({'refresh': str(session_tokens), 'access': str(session_tokens.access_token)}, status=status.HTTP_200_OK)
        except (TokenError, InvalidToken, User.DoesNotExist):
            return Response({'error': 'Invalid or expired token.'}, status=status.HTTP_401_UNAUTHORIZED)

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
        if 'profile_picture' not in request.FILES: return Response({'error': 'No file was submitted.'}, status=status.HTTP_400_BAD_REQUEST)
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

class FirstMatchView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, format=None):
        user_profile = request.user.profile
        user_interests = user_profile.interests.all()
        if not user_interests.exists(): return Response({'detail': 'User has no interests to match with.'}, status=status.HTTP_404_NOT_FOUND)
        potential_matches = Profile.objects.exclude(user=request.user).filter(interests__in=user_interests).distinct().first()
        if potential_matches:
            serializer = ProfileSerializer(potential_matches)
            return Response(serializer.data)
        else:
            return Response({'detail': 'No matches found at this time.'}, status=status.HTTP_404_NOT_FOUND)