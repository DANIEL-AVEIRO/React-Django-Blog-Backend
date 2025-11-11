from django.contrib.auth import authenticate, login, logout
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.decorators import permission_classes, api_view
from rest_framework.response import Response
from rest_framework import status
from django.core.mail import EmailMultiAlternatives
from django.template import Template, Context
from django.utils import timezone
import random
import datetime
from api.models import UserModel, EmailOTPModel


# ======================================================
# Utility Functions
# ======================================================
def generate_otp(length=6):
    return "".join([str(random.randint(0, 9)) for _ in range(length)])


def send_otp_email(user_email, otp_code):
    html_template = """
    <div style="font-family: Arial, sans-serif;max-width: 600px;margin:0 auto; padding:20px; border:1px solid #ddd;border-radius: 8px;background-color: #000;color:#fff;">
        <h2 style="color: #fff;text-align: center;">Verify Your Email Address</h2>
        <p style="font-size: 16px;color:#ccc;">Dear User,</p>
        <p style="font-size: 16px;color:#ccc;">To complete your registration or login, please use the following verification
            code:</p>
        <div style="text-align: center;margin:20px 0;">
            <span
                style="display: inline-block;font-size: 24px;font-weight: bold;color:#000;padding:10px 20px;border:1px solid #fff;border-radius: 5px;background-color: #fff;">
                {{ otp_code }}
            </span>
        </div>
        <p style="font-size: 16px;color:#ccc;">This code is valid for 15 minutes. Please do not share this code with anyone.</p>
        <p style="font-size: 16px;color:#ccc;">If you did not request this email, please ignore it.</p>
        <footer style="margin-top: 20px;text-align: center;font-size: 14px;color:#666;">
            <p>Thank you,<br>BookWorm Team</p>
        </footer>
    </div>
    """
    template = Template(html_template)
    context = Context({"otp_code": otp_code})
    html_content = template.render(context)

    subject = "Verify Your Email Address"
    msg = EmailMultiAlternatives(subject, "", None, [user_email])
    msg.attach_alternative(html_content, "text/html")
    msg.send()


# ======================================================
# Register API
# ======================================================
@api_view(["POST"])
@permission_classes([AllowAny])
def register(request):
    try:
        username = request.data.get("username")
        email = request.data.get("email")
        password = request.data.get("password")

        if not username or not email or not password:
            return Response(
                {"success": False, "message": "All fields are required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        existing_user = UserModel.objects.filter(email=email).first()

        if existing_user:
            if not existing_user.is_active:
                otp_code = generate_otp()
                EmailOTPModel.objects.update_or_create(
                    user=existing_user,
                    defaults={
                        "code": otp_code,
                        "expires_at": timezone.now() + datetime.timedelta(minutes=15),
                    },
                )
                send_otp_email(existing_user.email, otp_code)
                return Response(
                    {
                        "success": True,
                        "message": "Account already exists but not verified. We re-sent the OTP to your email.",
                    },
                    status=status.HTTP_200_OK,
                )

            return Response(
                {"success": False, "message": "Email already registered and verified"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = UserModel.objects.create_user(
            username=username,
            email=email,
            password=password,
        )
        user.is_active = False
        user.save()

        otp_code = generate_otp()
        EmailOTPModel.objects.create(
            user=user,
            code=otp_code,
            expires_at=timezone.now() + datetime.timedelta(minutes=15),
        )

        send_otp_email(user.email, otp_code)

        return Response(
            {
                "success": True,
                "message": "Verification code sent to your email. Please check.",
            },
            status=status.HTTP_200_OK,
        )

    except Exception as e:
        return Response(
            {
                "success": False,
                "message": f"User registration failed: {str(e)}",
            },
            status=status.HTTP_400_BAD_REQUEST,
        )


# ======================================================
# Verify OTP API
# ======================================================
@api_view(["POST"])
@permission_classes([AllowAny])
def verify_otp(request):
    email = request.data.get("email")
    otp = request.data.get("otp")

    if not otp or not email:
        return Response(
            {"success": False, "message": "Email and OTP are required"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        user = UserModel.objects.get(email=email)
        otp_entry = (
            EmailOTPModel.objects.filter(user=user, code=otp)
            .order_by("-created_at")
            .first()
        )

        if not otp_entry:
            return Response(
                {"success": False, "message": "Invalid OTP"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if otp_entry.is_expired():
            return Response(
                {"success": False, "message": "OTP expired"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.is_active = True
        user.save()

        token, _ = Token.objects.get_or_create(user=user)
        EmailOTPModel.objects.filter(user=user).delete()

        return Response(
            {
                "success": True,
                "message": "OTP verified successfully",
                "token": token.key,
                "user": {"username": user.username, "email": user.email},
            },
            status=status.HTTP_201_CREATED,
        )

    except UserModel.DoesNotExist:
        return Response(
            {"success": False, "message": "User does not exist"},
            status=status.HTTP_400_BAD_REQUEST,
        )


# ======================================================
# Login API
# ======================================================
@api_view(["POST"])
@permission_classes([AllowAny])
def login_view(request):
    try:
        email = request.data.get("email")
        password = request.data.get("password")

        if not email or not password:
            return Response(
                {"success": False, "message": "All fields are required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = authenticate(request, email=email, password=password)
        if not user:
            return Response(
                {"success": False, "message": "Invalid credentials"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        if not user.is_active:
            return Response(
                {"success": False, "message": "Please verify your email before login."},
                status=status.HTTP_403_FORBIDDEN,
            )

        login(request, user)
        token, _ = Token.objects.get_or_create(user=user)

        return Response(
            {
                "success": True,
                "message": "Login successful",
                "token": token.key,
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                },
            },
            status=status.HTTP_200_OK,
        )

    except Exception as e:
        return Response(
            {"success": False, "message": f"Login failed: {str(e)}"},
            status=status.HTTP_400_BAD_REQUEST,
        )


# ======================================================
# Logout API
# ======================================================
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def logout_view(request):
    try:
        token = getattr(request.user, "auth_token", None)
        if token:
            token.delete()
        logout(request)
        return Response(
            {"success": True, "message": "Logout successful"},
            status=status.HTTP_200_OK,
        )
    except Exception as e:
        return Response(
            {"success": False, "message": f"Logout failed: {str(e)}"},
            status=status.HTTP_400_BAD_REQUEST,
        )


# ======================================================
# Authenticated
# ======================================================
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def authenticated(request):
    user = request.user
    return Response(
        {
            "success": True,
            "user": {
                "username": user.username,
                "email": user.email,
                "profile": (user.profile.url if user.profile else None),
            },
        },
        status=status.HTTP_200_OK,
    )


# ======================================================
# Me
# ======================================================
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def me(request):
    user = request.user
    return Response(
        {
            "success": True,
            "user": {
                "username": user.username,
                "email": user.email,
                "profile": (user.profile.url if user.profile else None),
            },
        },
        status=status.HTTP_200_OK,
    )
