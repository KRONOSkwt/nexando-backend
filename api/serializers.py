# api/serializers.py

from rest_framework import serializers
from .models import Profile, Interest
from django.contrib.auth.models import User

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

class UserCreateSerializer(serializers.ModelSerializer):
    # Definimos los campos que el frontend nos enviará para el registro
    first_name = serializers.CharField(write_only=True, required=True)
    password = serializers.CharField(write_only=True, required=True)
    
    class Meta:
        model = User
        fields = ('email', 'password', 'first_name')

    def create(self, validated_data):
        """
        Este método se ejecuta cuando llamamos a serializer.save()
        y se encarga de la lógica de creación.
        """
        first_name = validated_data.pop('first_name')
        email = validated_data['email']
        password = validated_data.pop('password')

        user = User.objects.create_user(username=email, email=email, password=password)

        Profile.objects.create(user=user, first_name=first_name)

        return user