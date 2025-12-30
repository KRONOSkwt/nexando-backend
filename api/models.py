from django.db import models
from django.contrib.auth.models import User

"""
MODELOS DE DATOS BASE
"""

class Interest(models.Model):
    name = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return self.name

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True)
    first_name = models.CharField(max_length=100)
    profile_picture_url = models.ImageField(upload_to='profiles/', blank=True, null=True)
    city = models.CharField(max_length=100, blank=True)
    bio = models.TextField(blank=True)
    interests = models.ManyToManyField(
        Interest,
        through='UserInterest',
        related_name='profiles'
    )

    def __str__(self):
        return self.user.username

class UserInterest(models.Model):
    """
    Tabla intermedia para intereses ponderados (Primarios vs Secundarios).
    """
    profile = models.ForeignKey(Profile, on_delete=models.CASCADE)
    interest = models.ForeignKey(Interest, on_delete=models.CASCADE, db_index=True)
    is_primary = models.BooleanField(default=False)

    class Meta:
        unique_together = ('profile', 'interest')

    def __str__(self):
        return f"{self.profile.user.username} - {self.interest.name}"

"""
MODELOS DE INTERACCIÓN Y MATCHING
"""

class MatchAction(models.Model):
    class Action(models.TextChoices):
        LIKE = 'like', 'Like'
        PASS = 'pass', 'Pass'

    actor = models.ForeignKey(User, related_name='sent_actions', on_delete=models.CASCADE)
    target = models.ForeignKey(User, related_name='received_actions', on_delete=models.CASCADE)
    action = models.CharField(max_length=4, choices=Action.choices)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('actor', 'target')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['actor', 'target', 'action']),
        ]

class Connection(models.Model):
    user1 = models.ForeignKey(User, related_name='connections_as_user1', on_delete=models.CASCADE)
    user2 = models.ForeignKey(User, related_name='connections_as_user2', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user1', 'user2')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user1', 'user2']),
        ]