from django.contrib import admin
from allauth.socialaccount.admin import SocialAccountAdmin
from allauth.socialaccount.models import SocialAccount

@admin.register(SocialAccount)
class CustomSocialAccountAdmin(SocialAccountAdmin):
    list_display = ('__str__',)