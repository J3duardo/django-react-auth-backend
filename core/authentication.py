import jwt 
import datetime
from django.http import HttpRequest
from os import environ
from rest_framework.exceptions import AuthenticationFailed #type: ignore
from rest_framework.authentication import BaseAuthentication #type: ignore
from rest_framework.authentication import get_authorization_header #type: ignore
from rest_framework.response import Response #type: ignore
from rest_framework import status # type: ignore
from .models import User

access_secret = str(environ.get("ACCESS_TOKEN_SECRET"))
refresh_secret = str(environ.get("REFRESH_TOKEN_SECRET"))


class JwtAuth(BaseAuthentication):
  """Middleware para verificar si el usuario está autenticado"""
  def authenticate(self, request: HttpRequest):
    auth = get_authorization_header(request).decode("utf-8").split()

    if auth and len(auth) == 2:
      token = auth[1]
      payload = decode_access_token(token)
      user = User.objects.filter(id=payload["user_id"]).first()

      if user is None:
        raise AuthenticationFailed({"message": "User not found"})

      return (user, token)

    raise AuthenticationFailed({"message": "Unauthorized: You must be logged in to access this resource"})


def create_access_token(user_id: int):
  access_token = jwt.encode({
    "user_id": user_id,
    "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
    "iat": datetime.datetime.utcnow()
  }, access_secret, algorithm="HS256")

  return access_token


def create_refresh_token(user_id: int):
  refresh_token = jwt.encode({
    "user_id": user_id,
    "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7),
    "iat": datetime.datetime.utcnow()
  }, refresh_secret, algorithm="HS256")

  return refresh_token


def decode_access_token(token: str):
  try:
    payload = jwt.decode(jwt=token, key=access_secret, algorithms=["HS256"])
    return payload
  except Exception as e:
    print("Exception in function decode_access_token:", e)
    raise AuthenticationFailed({"message": e})
  

def decode_refresh_token(token: str):
  try:
    payload = jwt.decode(jwt=token, key=refresh_secret, algorithms=["HS256"])
    return payload
  except Exception as e:
    print("Exception in function decode_refresh_token:", e)
    raise AuthenticationFailed({"message": e})