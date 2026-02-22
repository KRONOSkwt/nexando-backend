import pytest
from django.contrib.auth.models import User
from api.models import Profile

@pytest.mark.django_db
def test_user_and_profile_creation():
    # Test User creation
    user = User.objects.create_user(username="testuser", password="password123")
    assert user.username == "testuser"
    
    # Profile is created by a signal? Let me check if a signal exists or if I need to create it manually
    # Looking at the code earlier, there was no mention of signals, but Profil has a OneToOne with User.
    # Usually in Django apps like this, there might be a signal or it's manual.
    # If it's manual:
    profile = Profile.objects.create(user=user, first_name="Test", city="Madrid", bio="Hello world")
    
    assert Profile.objects.count() == 1
    assert profile.user.username == "testuser"
    assert profile.first_name == "Test"
    assert profile.city == "Madrid"
    assert profile.bio == "Hello world"
    
    # Test __str__
    assert str(profile) == "testuser"
