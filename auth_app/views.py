from allauth.socialaccount.providers.facebook.views import FacebookOAuth2Adapter
from dj_rest_auth.registration.views import SocialLoginView
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from django.conf import settings
from django.utils import timezone
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from .serializers import UserRegistrationSerializer,UserLoginSerializer,UserProfileSerializer,UserChangePasswordSerializer,SendPasswordResetEmailSerializer,UserPasswordResetSerializer,SendOTPSerializer
from .renderers import UserRenderer
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.core.mail import send_mail
from django.utils.timezone import now, timedelta
from twilio.rest import Client
from .models import User
import random
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

class FacebookLogin(SocialLoginView):
    adapter_class = FacebookOAuth2Adapter

class GoogleLogin(SocialLoginView):
    adapter_class = GoogleOAuth2Adapter

    def post(self, request, *args, **kwargs):
        print("Access token:", request.data.get("access_token"))
        return super().post(request, *args, **kwargs)


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    user.access_token= refresh.access_token
    user.refresh_token=refresh
    user.save()
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class UserRegistrationView(APIView):
    renderer_classes = [UserRenderer]

    @swagger_auto_schema(
        request_body=UserRegistrationSerializer,
        responses={201: openapi.Response("Registration Success")},
        operation_description="Register a new user and return access and refresh tokens.",
    )

    def post(self, request, format=None):
        serializer = UserRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        token = get_tokens_for_user(user)
        return Response({'token': token, 'msg': 'Registration Success'}, status=status.HTTP_201_CREATED)


class UserLoginView(APIView):
    renderer_classes = [UserRenderer]

    @swagger_auto_schema(
        operation_description="Authenticate user and return access and refresh tokens.",
        request_body=UserLoginSerializer,
        responses={
            200: openapi.Response("Login Success", schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    "token": openapi.Schema(type=openapi.TYPE_OBJECT, properties={
                        "refresh": openapi.Schema(type=openapi.TYPE_STRING, description="Refresh Token"),
                        "access": openapi.Schema(type=openapi.TYPE_STRING, description="Access Token"),
                    }),
                    "msg": openapi.Schema(type=openapi.TYPE_STRING, description="Message"),
                },
            )),
            404: "Invalid email or password",
        },
    )

    def post(self, request, format=None):
        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data.get('email')
        password = serializer.data.get('password')
        user = authenticate(email=email, password=password)
        if user is not None:
            token = get_tokens_for_user(user)
            return Response({'token': token, 'msg': 'Login Success'}, status=status.HTTP_200_OK)
        else:
            return Response({'errors': {'non_field_errors': ['Email or Password is not Valid']}},
                            status=status.HTTP_404_NOT_FOUND)


class UserProfileView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Get user profile details.",
        responses={
            200: UserProfileSerializer,
        },
    )
    def get(self, request, format=None):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class UserChangePasswordView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Change the password of the logged-in user.",
        request_body=UserChangePasswordSerializer,
        responses={
            200: openapi.Response("Password Changed Successfully"),
            400: "Validation Error",
        },
    )
    def post(self, request, format=None):
        serializer = UserChangePasswordSerializer(data=request.data, context={'user': request.user})
        serializer.is_valid(raise_exception=True)
        return Response({'msg': 'Password Changed Successfully'}, status=status.HTTP_200_OK)


class SendPasswordResetEmailView(APIView):
    renderer_classes = [UserRenderer]

    @swagger_auto_schema(
        operation_description="Send a password reset email to the user.",
        request_body=SendPasswordResetEmailSerializer,
        responses={
            200: openapi.Response("Password Reset Link Sent"),
            400: "Validation Error",
        },
    )

    def post(self, request, format=None):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'msg': 'Password Reset link send. Please check your Email'}, status=status.HTTP_200_OK)


class UserPasswordResetView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, uid, token, format=None):
        serializer = UserPasswordResetSerializer(data=request.data, context={'uid': uid, 'token': token})
        serializer.is_valid(raise_exception=True)
        return Response({'msg': 'Password Reset Successfully'}, status=status.HTTP_200_OK)


class SendOtpView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Send an OTP to the user's registered email.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, description='Registered email address'),
            },
            required=['email'],
        ),
        responses={
            200: openapi.Response(description="OTP sent to the email"),
            404: openapi.Response(description="User with this email does not exist"),
        },
    )

    def post(self, request, format=None):
        email = request.data.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            otp = random.randint(100000, 999999)  # Generate a 6-digit OTP
            user.OTP = otp
            user.OTP_created_at = timezone.now()
            user.save()
            send_mail(
                subject='Your OTP for Password Reset',
                message=f'Your OTP for password reset is {otp}. It is valid for 5 minutes.',
                from_email='noreply@yourdomain.com',
                recipient_list=[email],
                fail_silently=False,
            )
            return Response({'msg': 'OTP sent to your email'}, status=status.HTTP_200_OK)
        else:
            return Response({'errors': {'email': 'User with this email does not exist'}},
                            status=status.HTTP_404_NOT_FOUND)

class VerifyOtpAndResetPasswordView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Verify OTP and reset the password.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, description="Registered email"),
                'otp': openapi.Schema(type=openapi.TYPE_STRING, description="6-digit OTP"),
                'password': openapi.Schema(type=openapi.TYPE_STRING, description="New password"),
                'password2': openapi.Schema(type=openapi.TYPE_STRING, description="Confirm new password"),
            },
            required=['email', 'otp', 'password', 'password2'],
        ),
        responses={
            200: openapi.Response("Password Reset Successfully"),
            400: "Validation Error",
        },
    )

    def post(self, request, format=None):
        email = request.data.get('email')
        otp = request.data.get('otp')
        password = request.data.get('password')
        password2 = request.data.get('password2')
        if password != password2:
            return Response({'errors': {'password': 'Passwords must match'}},status=status.HTTP_400_BAD_REQUEST)
        else:
            if not User.objects.filter(email=email).exists():
                return Response({'errors': {'email': 'User with this email does not exist'}},
                                status=status.HTTP_404_NOT_FOUND)

            user = User.objects.get(email=email)
            otp_entry = user.OTP
            if otp_entry == otp:
                time_diff = timezone.now() - user.OTP_created_at
                if time_diff > timedelta(minutes=5):
                    user.OTP = None
                    user.OTP_created_at = None
                    user.save()
                    return Response({"detail": "OTP has expired."}, status=status.HTTP_400_BAD_REQUEST)
                if password != password2:
                    return Response({'errors': {'password': 'Password and Confirm Password do not match'}},
                                    status=status.HTTP_400_BAD_REQUEST)
                user.OTP = None
                user.OTP_created_at = None
                user.set_password(password)
                user.save()

                return Response({'msg': 'Password reset successfully'}, status=status.HTTP_200_OK)
            else:
                return Response({'errors': {'otp': 'Invalid or expired OTP'}}, status=status.HTTP_400_BAD_REQUEST)


class SendPhoneOtpView(APIView):
    @swagger_auto_schema(
        operation_description="Send an OTP to the user's registered phone number.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'phone_number': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="The user's registered phone number in E.164 format."
                ),
            },
            required=['phone_number'],
        ),
        responses={
            200: openapi.Response(
                description="OTP sent successfully",
                examples={
                    "application/json": {"msg": "OTP sent successfully"}
                },
            ),
            404: openapi.Response(
                description="User with this phone number does not exist",
                examples={
                    "application/json": {"errors": {"phone_number": "User with this phone number does not exist"}}
                },
            ),
        },
    )
    def post(self, request, *args, **kwargs):
        serializer = SendOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        phone_number = serializer.validated_data['phone_number']
        if not User.objects.filter(phone_number=phone_number).exists():
            return Response({'errors': {'phone_number': 'User with this phone number does not exist'}},
                            status=status.HTTP_404_NOT_FOUND)

        user = User.objects.get(phone_number=phone_number)
        otp = random.randint(100000, 999999)
        user.phone_otp = str(otp)
        user.phone_otp_created_at = now()
        user.save()

        client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
        client.messages.create(
            body=f'Your OTP is {otp}',
            from_=settings.TWILIO_PHONE_NUMBER,
            to=phone_number
        )

        return Response({'msg': 'OTP sent successfully'}, status=status.HTTP_200_OK)

class VerifyOTPView(APIView):
    @swagger_auto_schema(
        operation_description="Verify the OTP sent to the phone number and reset the user's password.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'phone_number': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="The user's registered phone number in E.164 format."
                ),
                'otp': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="The OTP sent to the user's phone number."
                ),
                'password': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="The new password for the user."
                ),
                'password2': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Confirmation of the new password."
                ),
            },
            required=['phone_number', 'otp', 'password', 'password2'],
        ),
        responses={
            200: openapi.Response(
                description="OTP verified successfully and password reset.",
                examples={
                    "application/json": {"msg": "OTP verified successfully"}
                },
            ),
            400: openapi.Response(
                description="Validation error (e.g., OTP expired, invalid, or passwords don't match).",
                examples={
                    "application/json": {"errors": {"otp": "Invalid OTP"}},
                    "application/json": {"errors": {"password": "Passwords must match"}},
                },
            ),
            404: openapi.Response(
                description="User with this phone number not found.",
                examples={
                    "application/json": {"errors": {"phone_number": "User not found"}},
                },
            ),
        },
    )
    def post(self, request, *args, **kwargs):
        phone_number = request.data.get('phone_number')
        otp = request.data.get('otp')
        password = request.data.get('password')
        password2 = request.data.get('password2')
        if password != password2:
            return Response({'errors': {'password': 'Passwords must match'}}, status=status.HTTP_400_BAD_REQUEST)
        else:
            try:
                user = User.objects.get(phone_number=phone_number)
            except User.DoesNotExist:
                return Response({'errors': {'phone_number': 'User not found'}}, status=status.HTTP_404_NOT_FOUND)

            if user.phone_otp == otp:
                if now() - user.phone_otp_created_at > timedelta(minutes=5):
                    user.phone_otp = None
                    user.phone_otp_created_at = None
                    user.save()
                    return Response({'errors': {'otp': 'OTP has expired'}}, status=status.HTTP_400_BAD_REQUEST)


                user.phone_otp = None
                user.phone_otp_created_at = None
                user.set_password(password)
                user.save()

                return Response({'msg': 'OTP verified successfully'}, status=status.HTTP_200_OK)
            else:
                return Response({'errors': {'otp': 'Invalid OTP'}}, status=status.HTTP_400_BAD_REQUEST)

