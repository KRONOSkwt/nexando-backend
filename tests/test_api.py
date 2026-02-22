import pytest
from django.contrib.auth.models import User
from rest_framework.test import APIClient
from api.models import Profile, Interest, UserInterest

@pytest.mark.django_db
def test_recommendation_view_matching_interests():
    client = APIClient()
    
    # Create Interest
    interest_python = Interest.objects.create(name="Python")
    interest_django = Interest.objects.create(name="Django")
    interest_react = Interest.objects.create(name="React")
    
    # Create User 1 (The requester)
    user1 = User.objects.create_user(username="user1@example.com", password="password123")
    profile1 = Profile.objects.create(user=user1, first_name="User One")
    UserInterest.objects.create(profile=profile1, interest=interest_python)
    UserInterest.objects.create(profile=profile1, interest=interest_django)
    
    # Create User 2 (Should be recommended - has common interest)
    user2 = User.objects.create_user(username="user2@example.com", password="password123")
    profile2 = Profile.objects.create(user=user2, first_name="User Two")
    UserInterest.objects.create(profile=profile2, interest=interest_python) # Common interest
    
    # Create User 3 (Should NOT be recommended - no common interest)
    user3 = User.objects.create_user(username="user3@example.com", password="password123")
    profile3 = Profile.objects.create(user=user3, first_name="User Three")
    UserInterest.objects.create(profile=profile3, interest=interest_react) # Different interest
    
    # Authenticate user1
    client.force_authenticate(user=user1)
    
    # Call RecommendationView
    response = client.get('/api/v1/matches/recommendations/')
    
    assert response.status_code == 200
    # The response is paginated
    results = response.data.get('results', response.data)
    
    user_ids = [res['id'] for res in results]
    assert user2.id in user_ids
    assert user3.id not in user_ids
    assert user1.id not in user_ids
