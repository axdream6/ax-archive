from django.urls import path
from rest_framework.routers import DefaultRouter
from custom.api.views import UserListView

urlpatterns = []
router = DefaultRouter()
router.register('user', UserListView, basename='user')
urlpatterns += router.urls