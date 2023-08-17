from django.db import models
from django.contrib.auth.models import AbstractUser
from django_backblaze_b2 import BackblazeB2Storage
from django.dispatch import receiver
from django.db.models.signals import post_save
from typing import Any
from django.utils.crypto import get_random_string
from django.core.validators import (
  MinLengthValidator,
  RegexValidator,
  FileExtensionValidator,
  validate_image_file_extension
)



default_avatar = "https://res.cloudinary.com/dzytlqnoi/image/upload/v1641834084/chat-app/user-avatar/JEdwardo/vwprmdcnzkbwnup6oorg.jpg"
allowed_image_types = ["png", "jpeg", "jpg", "webp"]


# NOTA: AL EXTENDER EL MODEL NATIVO DEL USER DE DJANGO
# DEBE EJECUTARSE LA MIGRACIÓN INICIAL INCLUYENDO
# EL MODEL EXTENDIDO DEL USER, DE LO CONTRARIO DARÁ ERROR
# YA QUE EL USUARIO SERÁ CREADO EN LA DB USANDO
# EL MODEL ORIGINAL EN LUGAR DEL MODEL EXTENDIDO
class User(AbstractUser):
  username = None
  first_name = models.CharField(max_length=60, validators=[RegexValidator(r"^[A-Za-zÀ-ž]+$", "The first name must contain only letters with no white spaces")])
  last_name = models.CharField(max_length=60, validators=[RegexValidator(r"^[A-Za-zÀ-ž]+$", "The last name must contain only letters with no white spaces")])
  email = models.EmailField(max_length=100, unique=True)
  password = models.CharField(max_length=500, validators=[MinLengthValidator(6, "The password must contain at least 6 characters")])
  avatar = models.ImageField(
    upload_to="avatars",
    storage=BackblazeB2Storage,
    max_length=1,
    null=True,
    validators=[
      validate_image_file_extension,
      FileExtensionValidator(allowed_image_types, "Image must be of type .png, .jpg, .jpeg or .webp")
    ]
  )

  USERNAME_FIELD = "email" # Iniciar sesión con el email en lugar del username
  REQUIRED_FIELDS = []


class UserRefreshToken(models.Model):
  user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
  refresh_token = models.CharField(max_length=255)
  token_id = models.CharField(max_length=50, default="")
  expires_at = models.DateTimeField()
  created_at = models.DateTimeField(auto_now_add=True)

  # Generar automáticamente el token id al crearlo
  def save(self, *args: Any, **kwargs: Any) -> None:
    self.token_id = get_random_string(40)
    return super().save(*args, **kwargs)


class ResetPasswordToken(models.Model):
  user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="reset_password_token")
  token = models.CharField(max_length=50, null=True)
  expires_at = models.DateTimeField(null=True)


# Generar el registro en la tabla reset_password_token
# para el usuario automáticamente al registrarse
@receiver(post_save, sender=User)
def create_profile(sender: Any, instance: User, created: bool, **kwargs: Any):
  if created:
    reset_password_token = ResetPasswordToken(user=instance)
    reset_password_token.save()