from django.contrib import admin
from .models import Profile, Interest, UserInterest, MatchAction, Connection, Message, Feedback


# Configuración para ver los intereses DENTRO del perfil
class UserInterestInline(admin.TabularInline):
    model = UserInterest
    extra = 1
    autocomplete_fields = ['interest']

# N+1 Fix: list_select_related avoids per-row FK queries in the Admin list view
# (UserInterest.__str__ accesses profile.user.username and interest.name)
class UserInterestAdmin(admin.ModelAdmin):
    list_display = ('profile', 'interest', 'is_primary')
    list_filter = ('is_primary',)
    list_select_related = ('profile__user', 'interest')

class ProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'first_name', 'city')
    search_fields = ('user__username', 'first_name', 'city')
    inlines = [UserInterestInline]

class InterestAdmin(admin.ModelAdmin):
    search_fields = ['name']

# --- CONFIGURACIÓN PARA GESTIÓN DE FEEDBACK ---
class FeedbackAdmin(admin.ModelAdmin):
    list_display = ('user', 'content_preview', 'created_at', 'is_resolved')
    list_filter = ('is_resolved', 'created_at')
    search_fields = ('user__username', 'user__email', 'content')
    list_editable = ('is_resolved',)
    readonly_fields = ('user', 'content', 'created_at')

    def content_preview(self, obj):
        return obj.content[:50] + "..." if len(obj.content) > 50 else obj.content
    content_preview.short_description = "Contenido"

# Registro de modelos
admin.site.register(Profile, ProfileAdmin)
admin.site.register(Interest, InterestAdmin)
admin.site.register(UserInterest, UserInterestAdmin)
admin.site.register(MatchAction)
admin.site.register(Connection)
admin.site.register(Message)
admin.site.register(Feedback, FeedbackAdmin)