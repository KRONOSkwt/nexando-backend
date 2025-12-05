from rest_framework import serializers
from django.db import transaction
from django.contrib.auth.models import User
from .models import Profile, Interest, UserInterest

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

class InterestInputSerializer(serializers.Serializer):
    """
    Serializer para validar la entrada Y salida de cada objeto de interés.
    """
    # CORRECCIÓN CRÍTICA:
    # source='interest.name' le dice a DRF que para leer (GET),
    # debe navegar desde UserInterest -> Interest -> name.
    name = serializers.CharField(max_length=100, source='interest.name')
    is_primary = serializers.BooleanField()

class ProfileSerializer(serializers.ModelSerializer):
    """
    Serializer para leer y escribir en el Perfil, con lógica
    personalizada para manejar intereses ponderados.
    """
    interests = InterestInputSerializer(many=True, source='userinterest_set', required=False)

    class Meta:
        model = Profile
        fields = ['first_name', 'profile_picture_url', 'city', 'bio', 'interests']

    @transaction.atomic
    def update(self, instance, validated_data):
        # Nota: Al usar source='userinterest_set' en el campo, DRF pone los datos
        # validados bajo esa llave en validated_data.
        interests_data = validated_data.pop('userinterest_set', None)
        
        instance = super().update(instance, validated_data)

        if interests_data is not None:
            # Borramos los intereses antiguos
            UserInterest.objects.filter(profile=instance).delete()
            
            for interest_item in interests_data:
                # Al usar source='interest.name', DRF puede anidar la data de entrada.
                # Verificamos si viene como 'interest' dictionary o directo como 'name'
                # dependiendo de cómo DRF parsee la entrada con el source.
                # Para estar seguros, manejamos el diccionario plano que envía el frontend.
                
                # En un serializer.Serializer simple, validated_data suele respetar la estructura de entrada.
                # Sin embargo, el source podría moverlo.
                # Recuperamos el nombre de forma segura.
                interest_name = interest_item.get('name') or interest_item.get('interest', {}).get('name')
                
                if interest_name:
                    interest_name = interest_name.strip().title()
                    is_primary = interest_item.get('is_primary', False)
                    
                    interest_obj, _ = Interest.objects.get_or_create(name=interest_name)
                    
                    UserInterest.objects.create(
                        profile=instance,
                        interest=interest_obj,
                        is_primary=is_primary
                    )
        
        return instance

class ProfilePictureSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ['profile_picture_url']