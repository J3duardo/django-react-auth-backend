from django.http import HttpRequest, HttpResponse
from rest_framework.views import APIView #type: ignore
from rest_framework.response import Response #type: ignore
from rest_framework import status # type: ignore
import datetime
from os import environ
from django.utils import timezone
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from .models import User, UserRefreshToken, ResetPasswordToken
from .serializers import UserSerializer
from .authentication import (
  create_refresh_token,
  create_access_token,
  decode_refresh_token,
  JwtAuth
)


class UserSignupView(APIView):
  def post(self, req: HttpRequest):
    data= req.data #type: ignore

    if not data.get("password_confirm"): #type: ignore
      return Response({"message": "The password confirmation is required"}, status=status.HTTP_400_BAD_REQUEST)

    if data["password"] != data["password_confirm"]:
      return Response({"message": "Passwords don't match"}, status=status.HTTP_400_BAD_REQUEST)
    
    serializer = UserSerializer(data=data, many=False) #type: ignore

    if not serializer.is_valid():
      return Response({"message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    serializer.save() #type: ignore

    return Response({"data": {"user": serializer.data}})
  

class UserLoginView(APIView):
  def post(self, req: HttpRequest):
    email = req.data.get("email") #type: ignore
    password = req.data.get("password") #type: ignore

    if not email:
      return Response({"message": "The email is required"}, status=status.HTTP_400_BAD_REQUEST)
    
    if not password:
      return Response({"message": "The password is required"}, status=status.HTTP_400_BAD_REQUEST)
    
    user = User.objects.filter(email=email).first()

    if user is None:
      return Response({"message": "User not found or deleted"}, status=status.HTTP_404_NOT_FOUND)
    
    if not user.check_password(password): #type: ignore
      return Response({"message": "Wrong password"}, status=status.HTTP_400_BAD_REQUEST)
    
    access_token = create_access_token(user.id) #type: ignore
    refresh_token = create_refresh_token(user.id) #type: ignore
    serializer = UserSerializer(user, many=False) #type: ignore

    refresh_token_data = UserRefreshToken.objects.create(
      user=user,
      refresh_token=refresh_token,
      expires_at=datetime.datetime.utcnow() + datetime.timedelta(days=7)
    )

    HttpResponse().set_cookie("token_id", refresh_token)

    response = Response()
    response.set_cookie(key="token_id", value=refresh_token, httponly=True)
    response.data = {
      "data": {
        "user": serializer.data,
        "access_token": access_token,
        "refresh_token_id": refresh_token_data.token_id
      }
    }

    # Eliminar los refresh tokens expirados
    # que no hayan sido eliminados de la DB
    current_time = timezone.make_aware(datetime.datetime.utcnow(), timezone.utc)
    UserRefreshToken.objects.filter(user=user, expires_at__lte=current_time).delete()

    return response


class CurrentUserView(APIView):
  authentication_classes = [JwtAuth]
  
  def get(self, req: HttpRequest):
    user = req.user
    serializer = UserSerializer(user, many=False)

    return Response({"data": {"user": serializer.data}})
  

class RefreshTokenView(APIView):
  authentication_classes = [JwtAuth]

  def post(self, req: HttpRequest):
    token_id = req.GET.get("token-id")
    
    if token_id is None:
      return Response({"message": "The token id is required"}, status=status.HTTP_400_BAD_REQUEST)

    token_data = UserRefreshToken.objects.filter(user=req.user, token_id=token_id).first()

    if not token_data:
      return Response({"message": "Invalid or expired refresh token"}, status=status.HTTP_401_UNAUTHORIZED)
    
    # Verificar si el refresh token está expirado
    current_time = timezone.make_aware(datetime.datetime.utcnow(), timezone.utc)
    is_expired = token_data.expires_at <= current_time
    
    # Si el refresh token está expirado, eliminarlo de la base de datos
    if is_expired:
      token_data.delete()
      return Response({"message": "Expired session. Please, login again"}, status=status.HTTP_401_UNAUTHORIZED)

    # Decodificar el refresh token
    decoded_token = decode_refresh_token(token_data.refresh_token) #type: ignore
    user_id = decoded_token["user_id"]
    
    user = User.objects.filter(id=user_id).first()

    if user is None:
      return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    # Generar un nuevo access token
    access_token = create_access_token(user_id=user_id)
  
    return Response({
      "data": {
        "access_token": access_token
      }
    })
  

class UserLogoutView(APIView):
  """Cerrar la sesión específica del usuario"""

  authentication_classes = [JwtAuth]

  def post(self, req: HttpRequest):
    token_id = req.GET.get("token-id")
    
    if token_id is None:
      return Response({"message": "The token id is required"}, status=status.HTTP_400_BAD_REQUEST)

    refresh_token = UserRefreshToken.objects.filter(user=req.user, token_id=token_id).first()

    if refresh_token is None:
      return Response({"message": "Invalid token id"})
    
    refresh_token.delete()

    response = Response()
    response.delete_cookie(key="token_id")
    response.data = {"data": "User logged out successfully"}

    return response


class DeleteActiveRefreshTokensView(APIView):
  """Eliminar los refresh tokens activos del usuario excepto el de la sesión actual"""

  authentication_classes = [JwtAuth]

  def post(self, req: HttpRequest):
    current_token_id = req.GET.get("token-id")

    if current_token_id is None:
      return Response({"message": "The token id is required"}, status=status.HTTP_400_BAD_REQUEST)
    
    # Chequear si el refresh token es válido
    token_is_valid = UserRefreshToken.objects.filter(user=req.user, token_id=current_token_id).exists()

    if not token_is_valid:
      return Response({"message": "Invalid token id"}, status=status.HTTP_401_UNAUTHORIZED)

    # Eliminar los refresh tokens excepto el usado para hacer el request
    UserRefreshToken.objects.filter(user=req.user).exclude(token_id=current_token_id).delete()

    return Response({"data": "All active sessions deleted successfully"})
  

class ForgotPasswordView(APIView):
  def post(self, req: HttpRequest):
    data = req.data #type: ignore
    email = data.get("email") #type: ignore

    if email is None:
      return Response({"message": "The email address is required"}, status=status.HTTP_400_BAD_REQUEST)

    user = User.objects.filter(email=email).first()

    if user is None:
      return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    token = get_random_string(40)
    expires_at = datetime.datetime.now(tz=timezone.utc) + datetime.timedelta(minutes=30)

    user.reset_password_token.token = token #type: ignore
    user.reset_password_token.expires_at = expires_at #type: ignore
    user.reset_password_token.save() #type: ignore

    reset_password_link = f"{environ.get('APP_URL')}/api/reset-password?token={token}"
    email_body = f"Follow the next link to reset your password: {reset_password_link}"

    send_mail(
      subject="Reset your React-Django Auth account password",
      message=email_body,
      from_email="noreply@eshop.com",
      recipient_list=[email]
    )

    return Response({
      "data": f"An email was sent to {email} with instructions to reset your password"
    })
  

class ResetPasswordView(APIView):
  def post(self, req: HttpRequest):
    token = req.GET.get("token")

    if token is None:
      return Response({"message": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)

    data = req.data #type: ignore
    password = data.get("password") #type: ignore
    password_confirm = data.get("password_confirm") #type: ignore

    if password is None:
      return Response({"message": "The new password is required"}, status=status.HTTP_400_BAD_REQUEST)
    
    if len(password.strip()) < 6: #type: ignore
      return Response({"message": "The password must contain at least 6 characters"}, status=status.HTTP_400_BAD_REQUEST)
    
    if password_confirm is None:
      return Response({"message": "You must confirm your password"}, status=status.HTTP_400_BAD_REQUEST)
    
    if password != password_confirm:
      return Response({"message": "Passwords don't match"}, status=status.HTTP_400_BAD_REQUEST)
    
    reset_password = ResetPasswordToken.objects.filter(token=token).first()

    if reset_password is None:
      return Response({"message": "Invalid or expired token"}, status=status.HTTP_401_UNAUTHORIZED)
    
    # Verificar si el token está expirado
    current_time = timezone.make_aware(datetime.datetime.utcnow(), timezone.utc)
    is_expired = reset_password.expires_at <= current_time #type: ignore

    if is_expired:
      return Response({"message": "Expired token"}, status=status.HTTP_401_UNAUTHORIZED)
    
    # Actualizar la contraseña
    user = reset_password.user
    user.set_password(password) #type: ignore
    user.save()

    # Eliminar el token de la base de datos
    # y restablecer el expires at
    reset_password.token = None
    reset_password.expires_at = None
    reset_password.save()

    # Eliminar los refresh tokens de la base de datos
    UserRefreshToken.objects.filter(user=req.user).delete()
    
    return Response({"message": "Password updated successfully"})
