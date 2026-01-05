from django.contrib import admin
from .models import Profile, Interest, UserInterest, MatchAction, Connection

# Configuración para ver los intereses DENTRO del perfil
class UserInterestInline(admin.TabularInline):
    model = UserInterest
    extra = 1
    autocomplete_fields = ['interest']

# Configuración del Perfil
class ProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'first_name', 'city')
    search_fields = ('user__username', 'first_name', 'city')
    inlines = [UserInterestInline]

# Configuración de Intereses
class InterestAdmin(admin.ModelAdmin):
    search_fields = ['name']

# Registro de modelos
admin.site.register(Profile, ProfileAdmin)
admin.site.register(Interest, InterestAdmin)
admin.site.register(MatchAction)
admin.site.register(Connection)