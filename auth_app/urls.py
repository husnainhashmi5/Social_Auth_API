from django.urls import path, include
from auth_app.views import *

urlpatterns = [

    path('api/auth/', include('dj_rest_auth.urls')),  # Default Auth URLs
    path('api/auth/registration/', include('dj_rest_auth.registration.urls')),  # Registration
    path('api/auth/social/facebook/', FacebookLogin.as_view(), name='fb_login'),  # Facebook Login
    path('api/auth/social/google/', GoogleLogin.as_view(), name='google_login'), #google
    path('accounts/', include('allauth.urls')),  # Required for django-allauth
]
