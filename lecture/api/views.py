import json
from django.http import JsonResponse
from django.middleware.csrf import get_token
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_protect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework import status, generics
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework import (
    exceptions as rest_exceptions,
    response,
    viewsets,
    decorators as rest_decorators,
    permissions as rest_permissions,
)

from custom.models import User
from custom.api.serializers import UserSerializer
from .serializers import LectureSerializer, UpdateSerializer


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


def logoutView(request):
    if not request.user.is_authenticated:
        return JsonResponse({"detail": "You're not logged in"}, status=400)

    logout(request)
    return JsonResponse({"detail": "Successfully logged out"})


class WhoAmIView(APIView):
    authentication_classes = [SessionAuthentication]
    permission_classes = [IsAuthenticated]
    queryset = User.objects.all()

    @staticmethod
    def get(request, format=None):
        print(request.user.username)
        user = request.user
        data = {
            'full_name': user.first_name,
            'username': user.username,
            'email': user.email,
            # 'department': user.department
        }
        return JsonResponse(data, safe=False)


class LectureView(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    lookup_field = 'username'

    @action(detail=False, methods=['GET'])
    def by_username(self, request):
        username = request.query_params.get('username')
        user = User.objects.get(username=username)
        serializer = self.get_serializer(user)
        return Response(serializer.data)


class LectureOnlyView(APIView):
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


@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([rest_permissions.AllowAny])
# @method_decorator(csrf_protect, name='dispatch')
def registerView(request):
    serializer = LectureSerializer(data=request.data)
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
