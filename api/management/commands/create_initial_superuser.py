# api/management/commands/create_initial_superuser.py

import os
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User

class Command(BaseCommand):
    help = 'Crea un superusuario inicial de forma no interactiva usando variables de entorno'

    def handle(self, *args, **options):
        # Lee las credenciales desde las variables de entorno de Render
        username = os.environ.get('DJANGO_SUPERUSER_USERNAME')
        email = os.environ.get('DJANGO_SUPERUSER_EMAIL')
        password = os.environ.get('DJANGO_SUPERUSER_PASSWORD')

        if not all([username, email, password]):
            self.stdout.write(self.style.ERROR('Faltan variables de entorno para crear el superusuario.'))
            return

        # Comprueba si el usuario ya existe para no fallar en despliegues futuros
        if User.objects.filter(username=username).exists():
            self.stdout.write(self.style.SUCCESS(f'Superusuario "{username}" ya existe. Saltando creación.'))
        else:
            User.objects.create_superuser(username=username, email=email, password=password)
            self.stdout.write(self.style.SUCCESS(f'Superusuario "{username}" creado exitosamente.'))