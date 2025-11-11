from django.urls import path
from api import views

urlpatterns = [
    path("register/", views.register),
    path("login/", views.login_view),
    path("logout/", views.logout_view),
    path("authenticated/", views.authenticated),
    path("verify-otp/", views.verify_otp),
    path("me/", views.me),
]
