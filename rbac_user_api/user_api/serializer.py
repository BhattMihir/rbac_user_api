from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
import random
from .models import User

# serialization classes
class UserRegistrationSerializer(serializers.ModelSerializer):
    """
        User serializer for create user and get user.

        is_superuser is set to false because every other user will be
        normal user.
    """

    class Meta:
        model = User
        fields = ["email", "username", "password", "user_role", 
                "first_name", "last_name", "phone_no"]
        extra_kwargs = {"password": {"write_only": True}}

    def create(self, validated_data):

        if "phone_no" not in validated_data:
            raise serializers.ValidationError("Phone Number field is missing.")
        else:
            if len(str(validated_data["phone_no"])) < 10 or len(str(validated_data["phone_no"])) > 10:
                raise serializers.ValidationError("Invalid Phone Number.")

        validated_data["is_superuser"] = False

        auth_user = User.objects.create_user(**validated_data)

        return auth_user


class UserLoginSerializer(serializers.Serializer):
    """
        User login serializer to check if user is authenticated.
        and token is generated.
    """

    username = serializers.CharField(max_length=20)
    password = serializers.CharField(max_length=200, write_only=True)
    otp = serializers.CharField(read_only=True)
    access_token = serializers.CharField(read_only=True)
    refresh_token = serializers.CharField(read_only=True)
    user_role = serializers.CharField(read_only=True)
    message = serializers.CharField(read_only=True)
    url = serializers.CharField(read_only=True)

    def validate(self, data):
        """
            User credential validation including jwt token.
        """

        username = data['username']
        password = data['password']

        user = authenticate(username=username, password=password)

        if user:
            otp = random.randint(1000, 9999)
            user.otp = otp
            user.save()
            
            refresh = RefreshToken.for_user(user)
            refresh_token = str(refresh)
            access_token = str(refresh.access_token)

            validated_data = {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'username': user.username,
                'user_role': user.user_role,
                "otp": otp,
                "message": "Now validate otp with below url with get method and token.",
                "url": "verify_otp/{otp}"
            }

            return validated_data
        else:
            raise serializers.ValidationError("Invalid login credentials")


class ChangePasswordSerializer(serializers.Serializer):
    """
        Password change serializer for user.
    """

    username = serializers.CharField(max_length=20)
    old_password = serializers.CharField(max_length=20)
    new_password = serializers.CharField(max_length=20)

    def validate(self, data):
        """
            User credential validation for password change.
        """

        username = data['username']
        old_password = data['old_password']
        new_password = data['new_password']

        user = authenticate(username=username, password=old_password)

        if user:
        
            validated_data = {
                'user': user,
                'new_password': new_password
            }

            return validated_data

        raise serializers.ValidationError("Incorrect old password.")

    def create(self, validated_data):
        """
            Change password thing will be done here.
        """

        user = validated_data["user"]

        user.set_password(validated_data["new_password"])
        user.save()

        return user