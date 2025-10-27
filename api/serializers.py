# api/serializers.py

from rest_framework import serializers
from .models import Profile, Interest
from django.contrib.auth.models import User

# --- El Serializer de Creación se mantiene igual ---
class UserCreateSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(write_only=True, required=True)
    password = serializers.CharField(write_only=True, required=True)
    
    class Meta:
        model = User
        fields = ('email', 'password', 'first_name')

    def create(self, validated_data):
        first_name = validated_data.pop('first_name')
        email = validated_data['email']
        password = validated_data.pop('password')
        user = User.objects.create_user(username=email, email=email, password=password)
        Profile.objects.create(user=user, first_name=first_name)
        return user

# --- ProfileSerializer ACTUALIZADO con la lógica "Get or Create" ---
class ProfileSerializer(serializers.ModelSerializer):
    # Para LEER, seguimos mostrando los nombres de los intereses
    interests = serializers.SlugRelatedField(
        many=True,
        queryset=Interest.objects.all(), # El queryset es necesario para la validación inicial
        slug_field='name'
     )

    class Meta:
        model = Profile
        fields = ['first_name', 'profile_picture_url', 'city', 'bio', 'interests']

    def update(self, instance, validated_data):
        # 1. Extraemos los datos de los intereses antes de la actualización principal.
        interests_data = validated_data.pop('interests', None)
        
        # 2. Actualizamos todos los demás campos del perfil (first_name, bio, etc.)
        #    usando la lógica estándar del serializer.
        instance = super().update(instance, validated_data)

        # 3. Si el frontend nos envió una lista de intereses, la procesamos.
        if interests_data is not None:
            # Primero, borramos todos los intereses antiguos del usuario.
            # Esto maneja tanto adiciones como eliminaciones en una sola operación.
            instance.interests.clear()
            
            # Ahora, iteramos sobre la lista de strings que nos enviaron.
            for interest_name in interests_data:
                # LÓGICA CLAVE: "Get or Create"
                # - Intenta obtener un interés con ese nombre (ignorando mayúsculas/minúsculas y espacios).
                # - Si no existe, lo CREA.
                # - Devuelve el objeto de interés (ya sea el encontrado o el recién creado).
                interest_obj, created = Interest.objects.get_or_create(
                    name=interest_name.strip().title() # Limpiamos y estandarizamos el nombre
                )
                # Asociamos el interés encontrado/creado al perfil del usuario.
                instance.interests.add(interest_obj)
        
        instance.save()
        return instance

# --- El Serializer de la foto de perfil se mantiene igual ---
class ProfilePictureSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ['profile_picture_url']