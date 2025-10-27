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

# --- ProfileSerializer con la Lógica de Validación Corregida ---
class ProfileSerializer(serializers.ModelSerializer):
    # 1. Campo para LEER: Muestra los intereses existentes. No se usa para escribir.
    interests = serializers.SlugRelatedField(
        many=True,
        read_only=True, # ¡CRÍTICO! Este campo ya no aceptará datos de entrada.
        slug_field='name'
     )

    # 2. Campo para ESCRIBIR: Acepta una lista de strings sin validar si existen.
    #    Este campo solo se usa para la entrada de datos (PATCH/PUT).
    interest_names = serializers.ListField(
        child=serializers.CharField(max_length=100),
        write_only=True, # ¡CRÍTICO! Este campo no se mostrará en las respuestas GET.
        required=False # Es opcional al actualizar.
    )

    class Meta:
        model = Profile
        # Añadimos 'interest_names' a la lista de campos.
        fields = ['first_name', 'profile_picture_url', 'city', 'bio', 'interests', 'interest_names']

    def update(self, instance, validated_data):
        # 3. Lógica "Get or Create": Ahora buscamos 'interest_names' en los datos validados.
        interests_data = validated_data.pop('interest_names', None)
        
        # Actualizamos los otros campos del perfil normalmente.
        instance = super().update(instance, validated_data)

        if interests_data is not None:
            instance.interests.clear()
            for interest_name in interests_data:
                interest_obj, created = Interest.objects.get_or_create(
                    name=interest_name.strip().title()
                )
                instance.interests.add(interest_obj)
        
        instance.save()
        return instance

# --- El Serializer de la foto de perfil se mantiene igual ---
class ProfilePictureSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ['profile_picture_url']