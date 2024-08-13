from rest_framework import serializers
from .models import CustomUser
from django.contrib.auth import authenticate

class CustomUserSerializer(serializers.ModelSerializer):

    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'username', 'password']
        

class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    def validate(self, data):
        email = data.get("email")
        password = data.get("password")

        if email and password:
            user = authenticate(email=email, password=password)
            if user:
                if user.is_active:
                    data["user"] = user
                else:
                    msg = "User is deactivated."
                    raise serializers.ValidationError(msg)
            else:
                msg = "Invalid credentials."
                raise serializers.ValidationError(msg)
        else:
            msg = "Must provide email and password both."
            raise serializers.ValidationError(msg)
        return data