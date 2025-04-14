from rest_framework import serializers
from student.models import Student
from custom.models import User


class StudentSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(
        style={"input_type": "password"}, write_only=True)

    class Meta:
        model = User
        fields = [
            'username',
            'full_name',
            'email',
            'reg_number',
            'year_of_study',
            'password',
            'password2',

        ]
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError(
                {"password": "Passwords do not match"})

        return attrs

    def save(self, **kwargs):
        validated_data = self.validated_data
        user = User(
            username=validated_data['username'],
            full_name=validated_data['full_name'],
            email=validated_data['email'],
            reg_number=validated_data['reg_number'],
            year_of_study=validated_data['year_of_study'],
            role='Student',
        )
        user.set_password(validated_data['password'])
        user.save()

        # Optional: Create related Student model if applicable
        Student.objects.create(user=user)

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
        )
