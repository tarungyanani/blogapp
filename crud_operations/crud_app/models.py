from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.contrib.auth.models import AbstractUser, PermissionsMixin
from .manager import CustomUserManager
import re
from django.core.validators import RegexValidator

# Create your models here.
password_regex = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d).{8,}$'
password_validator = RegexValidator(
    regex=password_regex,
    message='Password must contain at least 8 characters, one uppercase letter, one lowercase letter, and one number',
)
email_regex =  r'^(?=.*\d).{8,}$'
email_validator = RegexValidator(
    regex=email_regex,
    message = 'Email must contain at least 8 characters, one uppercase letter, and one number',
)

class CustomUser(AbstractUser, PermissionsMixin):
    username = models.CharField(max_length=100, unique=True, null=True, blank=True)
    first_name = models.CharField(max_length=100, null=True, blank=True)
    last_name = models.CharField(max_length=100, null=True, blank=True)
    email = models.CharField(max_length=254, unique=True, validators=[email_validator])
    password = models.CharField(max_length=128, validators=[password_validator])
    phone = models.CharField(max_length=15, null=True, blank=True)
    gender = models.CharField(max_length=10, null=True, blank=True)
    dob = models.DateField(null=True, blank=True)
    bio = models.CharField(max_length=500, null=True, blank=True)
    forgot_password_token = models.CharField(max_length=100, null=True, blank=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
      return self.email

class ToDo(models.Model):
  user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True)
  title = models.CharField(max_length=100)
  description = models.TextField()
  created_at = models.DateField(default=timezone.now)
  updated_at = models.DateField(default=timezone.now)
  blog_image = models.ImageField(upload_to='todo_images/', blank=True, null=True)

  def __str__(self):
    return self.title

class Profile(models.Model):
  user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
  image = models.ImageField(default='default.jpg', upload_to='profile_pics/')

  def __str__(self):
    return f'{self.user.email} Profile'
  
class blog_image(models.Model):
  user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
  blog_image = models.ImageField(upload_to='blog_images/', blank=True, null=True)
  
  def __str__(self):
    return self.blog_image
  
class Like(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    todo = models.ForeignKey(ToDo, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'todo')

class Comment(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    todo = models.ForeignKey(ToDo, on_delete=models.CASCADE, related_name='comments')
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'Comment by {self.user.username} on {self.todo.title}'