import json
from django.http import JsonResponse
from django.middleware.csrf import get_token
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_protect
from django.contrib.auth import authenticate, login, logout
from django.views.decorators.http import require_POST
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import (
    exceptions as rest_exceptions,
    response,
    decorators as rest_decorators,
    permissions as rest_permissions,
)

from custom.api.serializers import UserSerializer
from custom.models import User
from .serializers import StudentSerializer, UpdateSerializer


@rest_decorators.api_view(["GET"])
def get_session_id(request):
    session_id = request.session.session_key
    return Response({'sessionId': session_id})


class getSession(APIView):
    authentication_classes = [SessionAuthentication]
    permission_classes = [IsAuthenticated]

    def get(request):
        # session_id = request.session.session_key
        return JsonResponse(request.session.session_key, safe=True)


def get_csrf(request):
    response = JsonResponse(
        {"Info": "Success - Set CSRF cookie", "Token": get_token(request)}
    )
    response["X-CSRFToken"] = get_token(request)
    token = get_token(request)

    print(token)
    return response


@ensure_csrf_cookie
def check_auth(request):
    if not request.user.is_authenticated:
        return JsonResponse({"isAuthenticated": False})

    return JsonResponse({"isAuthenticated": True})


@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([rest_permissions.AllowAny])
def loginView(request):
    email = request.data.get("email")
    password = request.data.get("password")

    if not email or not password:
        return JsonResponse({"Info": "Email and Password are needed"}, status=400)

    try:
        user_obj = User.objects.get(email__iexact=email)  # Case-insensitive
    except User.DoesNotExist:
        return JsonResponse({"Info": "User with given credentials does not exist"}, status=400)

    user = authenticate(request, username=user_obj.username, password=password)

    if user is None:
        return JsonResponse({"Info": "Incorrect password"}, status=400)

    login(request, user)
    return JsonResponse({"user": UserSerializer(user).data, "Info": "User logged in successfully"})


@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def logoutView(request):
    if not request.user.is_authenticated:
        return JsonResponse({"detail": "You're not logged in"}, status=400)

    logout(request)
    return JsonResponse({"detail": "Successfully logged out"})


class WhoAmIView(APIView):
    authentication_classes = [SessionAuthentication]
    permission_classes = [IsAuthenticated]

    @staticmethod
    def get(request, format=None):
        print(request.user.username)
        user = request.user
        data = {
            'full_name': user.full_name,
            'username': user.username,
            'email': user.email,
            # 'department': user.department,
        }
        return JsonResponse(data, safe=False)


class StudentOnlyView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        try:
            user = request.user
            user = UserSerializer(user)

            return Response({"user": user.data}, status=status.HTTP_200_OK)
        except:
            return Response(
                {"error": "Something went wrong when trying to load user"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


def get_user_data(request):
    user = request.user
    data = {
        'username': user.username,
        'email': user.email,
        # add any other user data you want to include
    }
    return JsonResponse(data)


@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([rest_permissions.AllowAny])
# @method_decorator(csrf_protect, name='dispatch')
def registerView(request):
    serializer = StudentSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    user = serializer.save()

    if user is not None:
        return response.Response(
            {
                "user": UserSerializer(user).data,
                "message": "Account created successfully",
            }
        )

    return rest_exceptions.AuthenticationFailed("Invalid credentials!")


@rest_decorators.api_view(['PUT', 'PATCH'])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def update_account(request):
    user = request.user
    serializer = UpdateSerializer(user, data=request.data, partial=True)

    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_404_NOT_FOUND)


@rest_decorators.api_view(['DELETE'])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def delete_account(request):
    user = request.user
    user.delete()
    return Response(status=status.HTTP_204_NO_CONTENT)
