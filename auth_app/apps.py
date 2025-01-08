from django.apps import AppConfig


class AuthAppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'auth_app'

    def ready(self):
        from allauth.socialaccount.models import SocialAccount
        def patched_socialaccount_str(self):
            return str(self.user)
        SocialAccount.__str__ = patched_socialaccount_str
