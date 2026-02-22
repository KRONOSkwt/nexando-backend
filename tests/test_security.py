import pytest
from django.contrib.auth.models import User
from rest_framework.test import APIClient

@pytest.mark.django_db
def test_chat_access_unauthenticated():
    client = APIClient()
    
    # Attempt to view messages for a user (unauthenticated)
    response = client.get('/api/v1/messages/1/')
    assert response.status_code in [401, 403]
    
    # Attempt to send a message (unauthenticated)
    response = client.post('/api/v1/messages/', {'recipient': 1, 'content': 'Hello'})
    assert response.status_code in [401, 403]

@pytest.mark.django_db
def test_conversation_access_denied_if_not_connected():
    client = APIClient()
    
    user1 = User.objects.create_user(username="user1@example.com", password="password123")
    user2 = User.objects.create_user(username="user2@example.com", password="password123")
    
    # Authenticate user1
    client.force_authenticate(user=user1)
    
    # Attempt to access user2's conversation without a Connection
    response = client.get(f'/api/v1/messages/{user2.id}/')
    
    # According to ConversationView code:
    # if not Connection.objects.filter(user1_id=u1, user2_id=u2).exists():
    #     raise PermissionDenied("Access denied")
    assert response.status_code == 403
