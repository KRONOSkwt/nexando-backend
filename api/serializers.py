from rest_framework import serializers
from django.db import transaction
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from .models import Profile, Interest, UserInterest, Message

# --- UTILS ---

class InterestInputSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=100, source='interest.name')
    is_primary = serializers.BooleanField(default=False)

# --- PROFILE SERIALIZERS ---

class ProfileSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(source='user.id', read_only=True)
    interests = InterestInputSerializer(many=True, source='userinterest_set', required=False)
    profile_picture_url = serializers.SerializerMethodField()

    class Meta:
        model = Profile
        fields = ['id', 'first_name', 'profile_picture_url', 'city', 'bio', 'interests']

    def get_profile_picture_url(self, obj):
        if obj.profile_picture_url:
            # Esto devuelve la URL completa de Cloudinary (https://res.cloudinary...)
            return obj.profile_picture_url.url 
        return None

    @transaction.atomic
    def update(self, instance, validated_data):
        interests_data = validated_data.pop('userinterest_set', None)
        instance = super().update(instance, validated_data)
        if interests_data is not None:
            UserInterest.objects.filter(profile=instance).delete()
            seen_interests = set()
            
            for item in interests_data:
                raw_name = item.get('name')
                if not raw_name and 'interest' in item:
                    raw_name = item['interest'].get('name')
                
                if raw_name:
                    clean_name = raw_name.strip().title()
                    if clean_name not in seen_interests:
                        seen_interests.add(clean_name)
                        interest_obj, _ = Interest.objects.get_or_create(name=clean_name)
                        UserInterest.objects.create(
                            profile=instance, 
                            interest=interest_obj, 
                            is_primary=item.get('is_primary', False)
                        )
        return instance

class ProfilePictureSerializer(serializers.ModelSerializer):
    profile_picture_url = serializers.SerializerMethodField()

    class Meta:
        model = Profile
        fields = ['profile_picture_url']

    def get_profile_picture_url(self, obj):
        if obj.profile_picture_url:
            return obj.profile_picture_url.url
        return None


class SignupSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(write_only=True, required=True)
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    interests = InterestInputSerializer(many=True, required=False)
    tokens = serializers.SerializerMethodField()
    class Meta:
        model = User
        fields = ('email', 'password', 'first_name', 'interests', 'tokens')
    def get_tokens(self, user):
        refresh = RefreshToken.for_user(user)
        return {'refresh': str(refresh), 'access': str(refresh.access_token)}
    @transaction.atomic
    def create(self, validated_data):
        first_name = validated_data.pop('first_name')
        interests_data = validated_data.pop('interests', [])
        password = validated_data.pop('password')
        email = validated_data.get('email')
        user = User.objects.create_user(username=email, email=email, password=password, is_active=True)
        profile = Profile.objects.create(user=user, first_name=first_name)
        
        if interests_data:
            seen_interests = set()
            for item in interests_data:
                raw_name = item.get('name') or item.get('interest', {}).get('name')
                if raw_name:
                    clean_name = raw_name.strip().title()
                    if clean_name not in seen_interests:
                        seen_interests.add(clean_name)
                        interest_obj, _ = Interest.objects.get_or_create(name=clean_name)
                        UserInterest.objects.create(
                            profile=profile, 
                            interest=interest_obj, 
                            is_primary=item.get('is_primary', False)
                        )
        return user

class UserCreateSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(write_only=True, required=True)
    password = serializers.CharField(write_only=True, required=False)
    class Meta:
        model = User
        fields = ('email', 'password', 'first_name')

# --- CHAT SERIALIZER ---

class MessageSerializer(serializers.ModelSerializer):
    sender_id = serializers.IntegerField(source='sender.id', read_only=True)
    recipient_id = serializers.IntegerField(source='recipient.id')

    class Meta:
        model = Message
        fields = ['id', 'sender_id', 'recipient_id', 'content', 'timestamp']
        read_only_fields = ['id', 'sender_id', 'timestamp']

    def validate_recipient_id(self, value):
        if not User.objects.filter(pk=value).exists():
            raise serializers.ValidationError("Recipient user does not exist.")
        return value

    def validate(self, data):
        request = self.context.get('request')
        recipient_user = data.get('recipient') 
        recipient_id = data.get('recipient_id')
        
        if not recipient_id and recipient_user:
            recipient_id = recipient_user.id

        if request and request.user.id == recipient_id:
             raise serializers.ValidationError("You cannot send messages to yourself.")
        return data