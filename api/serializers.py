# api/serializers.py

from rest_framework import serializers
from .models import Profile, Interest

class InterestSerializer(serializers.ModelSerializer):
    class Meta:
        model = Interest
        fields = ['name']

class ProfileSerializer(serializers.ModelSerializer):
    # Usamos SlugRelatedField para mostrar solo el nombre del interés
    interests = serializers.SlugRelatedField(
        many=True,
        read_only=True,
        slug_field='name'
     )

    class Meta:
        model = Profile
        # Definimos los campos que necesita el Frontend
        fields = ['first_name', 'profile_picture_url', 'city', 'bio', 'interests']