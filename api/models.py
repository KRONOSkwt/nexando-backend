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
    interests = models.ManyToManyField(
        Interest,
        through='UserInterest',
        related_name='profiles'
    )

    def __str__(self):
        return self.user.username

class UserInterest(models.Model):
    """
    Tabla intermedia que conecta un Perfil con un Interés,
    añadiendo la ponderación (si es primario o no).
    """
    profile = models.ForeignKey(Profile, on_delete=models.CASCADE)
    interest = models.ForeignKey(Interest, on_delete=models.CASCADE)
    is_primary = models.BooleanField(default=False)

    class Meta:
        unique_together = ('profile', 'interest')

    def __str__(self):
        return f"{self.profile.user.username} - {self.interest.name} ({'Primary' if self.is_primary else 'Secondary'})"
    
class MatchAction(models.Model):
    """
    Registra una acción (like/pass) de un usuario (actor)
    hacia otro usuario (target).
    """
    class Action(models.TextChoices):
        LIKE = 'like', 'Like'
        PASS = 'pass', 'Pass'

    actor = models.ForeignKey(
        User,
        related_name='sent_actions',
        on_delete=models.CASCADE
    )
    target = models.ForeignKey(
        User,
        related_name='received_actions',
        on_delete=models.CASCADE
    )
    action = models.CharField(
        max_length=4,
        choices=Action.choices
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('actor', 'target')
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.actor.username} --{self.action}--> {self.target.username}"