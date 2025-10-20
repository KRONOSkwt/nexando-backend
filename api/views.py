# api/views.py

from django.shortcuts import get_object_or_404
from django.contrib.auth.models import User
from django.db import IntegrityError

from rest_framework import generics, status
from rest_framework.views import APIView
from rest_framework.response import Response

from .models import Profile
from .serializers import ProfileSerializer, UserCreateSerializer

class ProfileDetailView(APIView):
    """
    Vista para recuperar un perfil de usuario por su ID.
    """
    def get(self, request, user_id, format=None):
        profile = get_object_or_404(Profile, pk=user_id)
        serializer = ProfileSerializer(profile)
        return Response(serializer.data, status=status.HTTP_200_OK)

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