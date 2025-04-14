from rest_framework import serializers
from lecture.models import Lecture
from custom.models import User


class LectureSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(
        style={"input_type": "password"}, write_only=True)

    class Meta:
        model = User
        fields = [
            "username",
            "full_name",
            "email",
            "employee_number",
            "title",
            "department",
            "password",
            "password2",

        ]
        extra_kwargs = {
            "password": {"write_only": True},
            "password2": {"write_only": True},
        }

    def validate(self, attrs):
        if attrs.get("password") != attrs.get("password2"):
            raise serializers.ValidationError(
                {"password": "Passwords do not match"})

        return attrs

    def save(self, **kwargs):
        validated_data = self.validated_data

        user = User(
            username=validated_data["username"],
            full_name=validated_data["full_name"],
            email=validated_data["email"],
            employee_number=validated_data["employee_number"],
            title=validated_data["title"],
            department=validated_data["department"],
            role="Lecture",
        )
        user.set_password(validated_data["password"])
        user.save()

        # Optional: if Lecture model stores extra lecture-specific info
        Lecture.objects.create(user=user)

        return user


class UpdateSerializer(serializers.ModelSerializer):
    full_name = serializers.CharField(required=False, allow_null=True)
    username = serializers.CharField(required=False, allow_null=True)
    email = serializers.EmailField(required=False, allow_null=True)
    # department = serializers.CharField(allow_null=True)

    class Meta:
        model = User
        fields = (
            "username",
            "full_name",
            "email",
            # "department",
        )
