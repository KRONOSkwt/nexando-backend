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
        interests_data = validated_data.pop('userinterest_set', None)
        
        instance = super().update(instance, validated_data)

        if interests_data is not None:
            UserInterest.objects.filter(profile=instance).delete()
            
            for interest_item in interests_data:
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