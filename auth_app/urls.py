from django.urls import path, include
from .views import *

Social = [

    path('auth/social/facebook/', FacebookLogin.as_view(), name='fb_login'),  # Facebook Login
    path('auth/social/google/', GoogleLogin.as_view(), name='google_login'), #google
    path('accounts/', include('allauth.urls')),  # Required for django-allauth
]




CustomUser = [
    path('register/',UserRegistrationView.as_view(),name="register"),
    path('login/',UserLoginView.as_view(),name="login"),
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('changepassword/', UserChangePasswordView.as_view(), name='changepassword'),
    path('send-reset-password-email/', SendPasswordResetEmailView.as_view(), name='send-reset-password-email'),
    path('reset-password/<uid>/<token>/', UserPasswordResetView.as_view(), name='reset-password'),
    path('send-otp/', SendOtpView.as_view(), name='send_otp'),
    path('verify-otp-reset-password/', VerifyOtpAndResetPasswordView.as_view(), name='verify_otp_reset_password'),
]


urlpatterns = Social + CustomUser