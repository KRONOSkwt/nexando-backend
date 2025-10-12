# api/admin.py

from django.contrib import admin
from .models import Profile, Interest

# Registramos nuestros modelos para que aparezcan en el panel de administración
admin.site.register(Profile)
admin.site.register(Interest)