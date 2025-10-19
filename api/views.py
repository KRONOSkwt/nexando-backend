# api/views.py

from rest_framework import generics 
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
from .models import Profile

from .serializers import ProfileSerializer, UserCreateSerializer 

class ProfileDetailView(APIView):
    """
    Vista para recuperar un perfil de usuario por su ID.
    """
    def get(self, request, user_id, format=None):
        # Busca el perfil asociado al user_id, si no existe devuelve 404
        profile = get_object_or_404(Profile, pk=user_id)
        serializer = ProfileSerializer(profile)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class ProfileCreateView(generics.CreateAPIView):
    """
    Vista para crear un nuevo Usuario y su Perfil asociado.
    Solo acepta peticiones POST.
    """
    serializer_class = UserCreateSerializer