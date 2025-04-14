from custom.models import User
from .serializers import UserSerializer
from rest_framework.views import APIView
from .filters import UserFilter
from rest_framework.response import Response
from rest_framework import viewsets, filters
from django_filters.rest_framework import DjangoFilterBackend

class UserListView(viewsets.ModelViewSet):
    serializer_class = UserSerializer
    queryset = User.objects.all()
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['username']
    ordering_fields = '__all__'