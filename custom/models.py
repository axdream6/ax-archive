from django.contrib.auth.models import AbstractUser
from django.db import models
from .manager import UserManager


class User(AbstractUser):
    username = models.CharField(max_length=50, unique=True)
    email = models.EmailField(unique=True)
    full_name = models.CharField(max_length=255)

    #is_student = models.BooleanField(default=False)
    #is_cr = models.BooleanField(default=False)
    #is_lecture = models.BooleanField(default=False)

    ROLE_CHOICES = (
        ('student', 'Student'),
        ('cr', 'Class Representative'),
        ('lecture', 'Lecture'),
    )
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, editable=False)
    
    def save(self, *args, **kwargs):
        if self.pk:
            old_role = User.objects.get(pk=self.pk).role
            if old_role != self.role:
                raise ValueError("You cannot change the role of a user once it's set.")
        super().save(*args, **kwargs)

    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Lecture
    employee_number = models.CharField(max_length=15, null=True, blank=True)
    TITLE_SELECT = (
        ("Head Of Department", "Head Of Department"),
        ("Lecture", "Lecture"),
    )
    title = models.CharField(
        max_length=100, choices=TITLE_SELECT, null=True, blank=True)
    DEPARTMENT_CHOICES = (
        ("Computer Science And Engineering", "Computer Science And Engineering"),
        ("Information And Communication Technology",
         "Information And Communication Technology"),
    )
    department = models.CharField(
        max_length=100, choices=DEPARTMENT_CHOICES, null=True, blank=True)

    # Student
    reg_number = models.CharField(max_length=15, null=True, blank=True)
    year_of_study = models.IntegerField(null=True, blank=True)

    objects = UserManager()

    def __str__(self):
        return self.username
