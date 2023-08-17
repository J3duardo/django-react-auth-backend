from django.urls import path
from .views import (
  UserSignupView,
  UserLoginView,
  CurrentUserView,
  UserLogoutView,
  RefreshTokenView,
  ForgotPasswordView,
  ResetPasswordView,
  DeleteActiveRefreshTokensView
)


urlpatterns = [
  path("signup/", UserSignupView.as_view(), name="signup"),
  path("login/", UserLoginView.as_view(), name="login"),
  path("me/", CurrentUserView.as_view(), name="me"),
  path("logout/", UserLogoutView.as_view(), name="logout"),
  path("refresh-token/", RefreshTokenView.as_view(), name="refresh_token"),
  path("forgot-password/", ForgotPasswordView.as_view(), name="forgot-password"),
  path("reset-password/", ResetPasswordView.as_view(), name="reset-password"),
  path("delete-active-tokens/", DeleteActiveRefreshTokensView.as_view(), name="delete-active-sessions")
]