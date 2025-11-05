# api/views.py

import os
from io import BytesIO
from PIL import Image
from django.core.files.base import ContentFile
from django.shortcuts import get_object_or_404
from django.db import IntegrityError
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta

# Imports de Django Rest Framework
from rest_framework import generics, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework_simplejwt.tokens import RefreshToken

# Imports locales
from .models import Profile
from .serializers import ProfileSerializer, UserCreateSerializer, ProfilePictureSerializer

# --- VISTAS DE AUTENTICACIÓN ---

class RequestMagicLinkView(APIView):
    """
    Vista para solicitar un "magic link" de inicio de sesión.
    Crea un usuario inactivo si no existe.
    """
    permission_classes = [AllowAny] # Cualquiera puede solicitar un enlace

    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        if not email:
            return Response({'error': 'Email is required.'}, status=status.HTTP_400_BAD_REQUEST)

        user, created = User.objects.get_or_create(
            username=email,
            defaults={'email': email, 'is_active': False}
        )

        token = RefreshToken.for_user(user)
        token.set_exp(lifetime=timedelta(minutes=15))
        
        # TODO: Mover la URL del frontend a una variable de entorno
        magic_link_url = f"http://localhost:3000/auth/magic-link/verify/?token={str(token.access_token)}"

        from sendgrid import SendGridAPIClient
        from sendgrid.helpers.mail import Mail

        message = Mail(
            from_email='noreply@nexando.ai',
            to_emails=email,
            subject='Your Magic Link to Nexando.ai',
            html_content=f'<strong>Welcome to Nexando!</strong><br>Click <a href="{magic_link_url}">here</a> to log in. This link is valid for 15 minutes.'
        )
        try:
            sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
            sg.send(message)
            return Response({'detail': 'If an account exists for this email, a magic link has been sent.'}, status=status.HTTP_200_OK)
        except Exception as e:
            # Log the error in a real application
            return Response({'error': 'Could not send magic link email.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# --- VISTAS DE PERFIL Y USUARIO ---

class UserProfileView(APIView):
    """
    Vista para LEER y ACTUALIZAR el perfil del usuario autenticado.
    """
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
    """
    Vista para subir y optimizar la foto de perfil del usuario autenticado.
    """
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
    """
    Vista para LEER un perfil público por su ID.
    """
    def get(self, request, user_id, format=None):
        profile = get_object_or_404(Profile, pk=user_id)
        serializer = ProfileSerializer(profile)
        return Response(serializer.data, status=status.HTTP_200_OK)

class ProfileCreateView(generics.CreateAPIView):
    """
    (Legacy) Vista para crear un nuevo Usuario y Perfil con contraseña.
    """
    serializer_class = UserCreateSerializer
    def create(self, request, *args, **kwargs):
        try:
            return super().create(request, *args, **kwargs)
        except IntegrityError:
            error_data = {'email': ['A user with that email already exists.']}
            return Response(error_data, status=status.HTTP_400_BAD_REQUEST)


# --- VISTA DE MATCHING ---

class FirstMatchView(APIView):
    """
    Vista para OBTENER el primer match para el usuario autenticado.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        user_profile = request.user.profile
        user_interests = user_profile.interests.all()

        if not user_interests.exists():
            return Response({'detail': 'User has no interests to match with.'}, status=status.HTTP_404_NOT_FOUND)
        
        potential_matches = Profile.objects.exclude(user=request.user) \
                                          .filter(interests__in=user_interests) \
                                          .distinct() \
                                          .first()

        if potential_matches:
            serializer = ProfileSerializer(potential_matches)
            return Response(serializer.data)
        else:
            return Response({'detail': 'No matches found at this time.'}, status=status.HTTP_404_NOT_FOUND)