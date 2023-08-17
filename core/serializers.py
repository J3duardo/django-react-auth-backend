from rest_framework.serializers import ModelSerializer #type: ignore
from typing import Any
from .models import User


class UserSerializer(ModelSerializer):
  class Meta:
    model = User
    fields = ["id", "first_name", "last_name", "email", "password", "avatar"]
    extra_kwargs = {
      # Al crear el usuario no se incluye la contraseña en la data de la respuesta
      "password": {"write_only": True}
    }

  # Hashear la contraseña automáticamente al crear el usuario
  def create(self, validated_data: Any):
    password = validated_data.pop("password", None)
    instance = self.Meta.model(**validated_data)

    if password is not None:
      instance.set_password(password)
    
    instance.save()

    return instance