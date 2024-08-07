from django.contrib import admin
from .models import ToDo, CustomUser

admin.site.register(ToDo)
admin.site.register(CustomUser)

# from django.contrib.auth.models import UserAdmin
# from .models import CustomUser

