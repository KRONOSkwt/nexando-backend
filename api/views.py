# api/views.py

import os
from io import BytesIO
from PIL import Image
from django.core.files.base import ContentFile
from django.shortcuts import get_object_or_404
from django.db import IntegrityError
from django.contrib.auth.models import User

from rest_framework import generics, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser # Para subida de archivos

from .models import Profile
from .serializers import ProfileSerializer, UserCreateSerializer, ProfilePictureSerializer

# --- VISTA PARA LEER Y ACTUALIZAR EL PERFIL DEL USUARIO AUTENTICADO ---
class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        serializer = ProfileSerializer(request.user.profile)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request, format=None):
        profile = request.user.profile
        # El partial=True permite actualizaciones parciales (PATCH)
        serializer = ProfileSerializer(profile, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# --- NUEVA VISTA para subir la foto de perfil ---
class ProfilePictureUploadView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser) # Habilita la subida de archivos

    def put(self, request, format=None):
        if 'profile_picture' not in request.FILES:
            return Response({'error': 'No file was submitted.'}, status=status.HTTP_400_BAD_REQUEST)

        file_obj = request.FILES['profile_picture']
        profile = request.user.profile

        # Lógica de optimización a WebP
        try:
            img = Image.open(file_obj)
            
            # Convertimos a WebP en memoria
            buffer = BytesIO()
            img.save(buffer, format='WEBP', quality=85) # Calidad del 85%
            buffer.seek(0)

            # Creamos un nombre de archivo único
            webp_filename = f'{profile.user.id}_{os.path.splitext(file_obj.name)[0]}.webp'
            
            # Guardamos la imagen optimizada
            profile.profile_picture_url.save(webp_filename, ContentFile(buffer.read()), save=True)

            serializer = ProfileSerializer(profile)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'error': f'Image processing failed: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# --- NUEVA VISTA para obtener el primer match ---
class FirstMatchView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        user_profile = request.user.profile
        user_interests = user_profile.interests.all()

        if not user_interests:
            return Response({'detail': 'User has no interests to match with.'}, status=status.HTTP_404_NOT_FOUND)

        # Lógica de Matching MVP:
        # 1. Excluirse a sí mismo
        # 2. Encontrar perfiles que compartan al menos 1 interés
        # 3. Ordenar por el que más intereses comparta (opcional pero bueno)
        # 4. Tomar el primero que no sea el mismo
        
        potential_matches = Profile.objects.exclude(user=request.user) \
                                          .filter(interests__in=user_interests) \
                                          .distinct() \
                                          .first() # Tomamos el primero para el MVP

        if potential_matches:
            serializer = ProfileSerializer(potential_matches)
            return Response(serializer.data)
        else:
            return Response({'detail': 'No matches found at this time.'}, status=status.HTTP_404_NOT_FOUND)

# --- VISTAS EXISTENTES ---
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