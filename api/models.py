# api/models.py

from django.db import models
from django.contrib.auth.models import User

class Interest(models.Model):
    name = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return self.name

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True)
    first_name = models.CharField(max_length=100)
    profile_picture_url = models.URLField(max_length=255, blank=True)
    city = models.CharField(max_length=100, blank=True)
    bio = models.TextField(blank=True)
    interests = models.ManyToManyField(Interest, blank=True)

    def __str__(self):
        return self.user.username