# api/serializers.py

from rest_framework import serializers
from .models import Profile, Interest
from django.contrib.auth.models import User

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

class ProfileSerializer(serializers.ModelSerializer):
    interests = serializers.SlugRelatedField(
        many=True,
        queryset=Interest.objects.all(),
        slug_field='name'
     )

    class Meta:
        model = Profile
        fields = ['first_name', 'profile_picture_url', 'city', 'bio', 'interests']

    def update(self, instance, validated_data):
        interests_data = validated_data.pop('interests', None)
        
        instance = super().update(instance, validated_data)

        if interests_data is not None:
            instance.interests.clear()
            for interest_name in interests_data:
                interest_obj, created = Interest.objects.get_or_create(name=interest_name.strip().title())
                instance.interests.add(interest_obj)
        
        instance.save()
        return instance

class ProfilePictureSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ['profile_picture_url']