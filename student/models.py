from django.db import models
from custom.models import User

# Create your models here.
class Student(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True, editable=False)
    