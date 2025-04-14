from django.db import models
from custom.models import User

# Create your models here.
class Lecture(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, editable=False)
    
   