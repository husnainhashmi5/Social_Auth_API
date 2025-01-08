# from django.contrib import admin
# from allauth.socialaccount.models import SocialAccount
#
# # Unregister the default admin registration
# admin.site.unregister(SocialAccount)
#
# # Re-register with a custom admin class
# @admin.register(SocialAccount)
# class SocialAccountAdmin(admin.ModelAdmin):
#     list_display = ('user', 'provider', 'custom_str')
#
#     def custom_str(self, obj):
#         # Ensure the display returns a proper string
#         try:
#             return str(obj.user)  # Or any other field that works as a string representation
#         except Exception as e:
#             return f"Error: {e}"
