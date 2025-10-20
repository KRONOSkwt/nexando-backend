# api/views.py

from rest_framework import generics 
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
from .models import Profile
from django.db import IntegrityError

from .serializers import ProfileSerializer, UserCreateSerializer 

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
    
class ProfileCreateView(generics.CreateAPIView):
    """
    Vista para crear un nuevo Usuario y su Perfil asociado.
    Solo acepta peticiones POST.
    """
    serializer_class = UserCreateSerializer