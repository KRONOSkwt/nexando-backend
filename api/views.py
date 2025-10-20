# api/views.py

from django.shortcuts import get_object_or_404
from django.db import IntegrityError

from rest_framework import generics, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

from .models import Profile
from .serializers import ProfileSerializer, UserCreateSerializer

class UserProfileView(APIView):
    """
    Vista para obtener el perfil del usuario actualmente autenticado.
    Requiere un token JWT válido.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        serializer = ProfileSerializer(request.user.profile)
        return Response(serializer.data, status=status.HTTP_200_OK)


# --- VISTA PARA LEER UN PERFIL PÚBLICO POR ID (GET) ---
class ProfileDetailView(APIView):
    """
    Vista para recuperar un perfil de usuario por su ID.
    """
    def get(self, request, user_id, format=None):
        profile = get_object_or_404(Profile, pk=user_id)
        serializer = ProfileSerializer(profile)
        return Response(serializer.data, status=status.HTTP_200_OK)


# --- VISTA PARA CREAR UN PERFIL (POST) ---
class ProfileCreateView(generics.CreateAPIView):
    """
    Vista para crear un nuevo Usuario y su Perfil asociado.
    Solo acepta peticiones POST y maneja errores de duplicados.
    """
    serializer_class = UserCreateSerializer

    def create(self, request, *args, **kwargs):
        try:
            return super().create(request, *args, **kwargs)
        except IntegrityError:
            error_data = {'email': ['A user with that email already exists.']}
            return Response(error_data, status=status.HTTP_400_BAD_REQUEST)