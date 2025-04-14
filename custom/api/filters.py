from django_filters import rest_framework as filters
from custom.models import User

class UserFilter(filters.FilterSet):
    # Define your filters here, e.g., for searching by name
    username = filters.CharFilter(lookup_expr='icontains')

    class Meta:
        model = User
        fields = ['username']
