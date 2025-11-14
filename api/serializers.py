from rest_framework import serializers
from django.db import transaction
from .models import Profile, Interest, UserInterest

class InterestInputSerializer(serializers.Serializer):
    """
    Serializer para validar la entrada de cada objeto de interés.
    """
    name = serializers.CharField(max_length=100)
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
            
            for interest_data in interests_data:
                interest_name = interest_data['name'].strip().title()
                is_primary = interest_data['is_primary']
                
                interest_obj, _ = Interest.objects.get_or_create(name=interest_name)
                
                UserInterest.objects.create(
                    profile=instance,
                    interest=interest_obj,
                    is_primary=is_primary
                )
        
        return instance