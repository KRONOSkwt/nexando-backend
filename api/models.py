from django.db import models
from django.contrib.auth.models import User
from django.core.validators import MaxLengthValidator

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
    # BAJA #17: Renombrado conceptualmente, mantenemos nombre DB para compatibilidad
    profile_picture_url = models.ImageField(upload_to='profiles/', blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, db_index=True) # MEDIO #4: Index en city
    bio = models.TextField(blank=True)
    interests = models.ManyToManyField(
        Interest,
        through='UserInterest',
        related_name='profiles'
    )

    def __str__(self):
        return self.user.username

class UserInterest(models.Model):
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

class Message(models.Model):
    """
    Modelo para almacenar mensajes de chat individuales.
    """
    sender = models.ForeignKey(User, related_name='sent_messages', on_delete=models.CASCADE)
    recipient = models.ForeignKey(User, related_name='received_messages', on_delete=models.CASCADE)
    
    # ALTA-01: Límite de caracteres para evitar DoS
    content = models.TextField(
        validators=[MaxLengthValidator(5000)]
    )
    timestamp = models.DateTimeField(auto_now_add=True)
    
    # MEDIO-06: Tracking de lectura
    read_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['timestamp']
        indexes = [
            models.Index(fields=['sender', 'recipient', 'timestamp']),
            models.Index(fields=['recipient', 'sender', 'timestamp']), # MEDIO-05: Índice Inverso
        ]

    def __str__(self):
        return f"{self.sender.username} -> {self.recipient.username}"