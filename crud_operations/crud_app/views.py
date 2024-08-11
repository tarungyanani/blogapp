from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
from django.contrib.auth.hashers import make_password, check_password
from .models import ToDo, CustomUser, Profile
from django.contrib.auth import logout
from django.views.decorators.csrf import csrf_protect
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from datetime import datetime
from django.contrib.auth.decorators import login_required
from .utils import send_email
from django.core.mail import send_mail
from django.conf import settings
import random
from django.utils import timezone
from .helpers import send_forget_password_email
import uuid
from django.views.decorators.cache import never_cache
from django.contrib import messages
from django.urls import reverse
from .serializer import LoginSerializer
from rest_framework.views import APIView
from rest_framework.response import Response

email_regex =  r'^(?=.*\d).{8,}$'
email_validator = RegexValidator(
    regex=email_regex,
    message = 'Email must contain at least 8 characters, one uppercase letter, and one number',
)
password_regex = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d).{8,}$'
password_validator = RegexValidator(
    regex=password_regex,
    message = 'Password must contain at least 8 characters, one uppercase letter, one lowercase letter, and one number',
)

def generate_otp():
    return random.randint(1000,9999)
    
def send_email(email, first_name, otp):
    subject = 'ToDo App'
    message = f'Hi {first_name}, Your OTP is {otp}'
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [email]
    send_mail(subject, message, email_from, recipient_list)


class LoginAPI(APIView):
    def post(self, request):
        try:
            data = request.data
            serializer = LoginSerializer(data=data)
            if serializer.is_valid():
                email = serializer.validated_data['email']
                password = serializer.validated_data['password']
                user = authenticate(request, email=email, password=password)
                if user:
                    login(request, user)
                    return Response({'message': 'Login Successful'})
                else:
                    return Response({'message': 'Invalid Credentials'}, status=400)
            else:
                return Response({'message': serializer.errors}, status=400)
        except Exception as e:
            return Response({'message': str(e)}, status=400)

@csrf_protect
@never_cache
def register_page(request):
    if request.method == 'POST':
        # username = request.POST.get('username')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        # phone = request.POST.get('phone')
        # profile_image = request.FILES.get('profile_image')

        try:
            email_validator(email)
        except ValidationError as e:
            error = "Email must contain at least 8 characters, one uppercase letter, and one number"
            return render(request, 'register.html', {'error': error})

        try:
            password_validator(password)
        except ValidationError as e:
            error = "Password must contain at least 8 characters, one uppercase letter, one lowercase letter, and one number"
            return render(request, 'register.html', {'error': error})
        
        if password != confirm_password:
            error = "Password and confirm password must be same."
            return render(request, 'register.html', {'error': error})
        
        if CustomUser.objects.filter(email=email).exists():
            error = "Email already exists"
            return render(request, 'register.html', {'error': error})
        
        otp = generate_otp()
        send_email(email, first_name, otp)
        request.session['otp'] = otp
        request.session['otp_time'] = timezone.now().timestamp()
        # request.session['username'] = username
        request.session['first_name'] = first_name
        request.session['last_name'] = last_name
        request.session['email'] = email
        request.session['password'] = password
        # request.session['phone'] = phone

        return redirect('verify_otp')
    return render(request, 'register.html')
        # if username and email and password and confirm_password:
        #     if password == confirm_password:  # Ensure all fields are provided
                # hashed_password = make_password(password)
                
                # user = CustomUser.objects.create(username=username, first_name=firstname, last_name=last_name, email=email, phone=phone)
                # user.set_password(password)
                # user.set_password(confirm_password)
                # Save the user object
                # send_email(email, username)
                # username = request.session.get('username')
                # firstname = request.session.get('first_name')
                # last_name = request.session.get('last_name')
                # email = request.session.get('email')
                # password = request.session.get('password')
                # # confirm_password = request.POST.get('confirm_password')
                # phone = request.session.get('phone')
                # # user.save()
                # # login(request, user)
                # # return redirect('login_page')
                # return redirect("verify_otp")
    #         else:
    #             error = "Password and confirm password must be same."
    #             return render(request, 'register.html', {'error': error})
        
    # return render(request, 'register.html')

@csrf_protect
def verify_otp(request):
    if request.method == "POST":
        user_otp = request.POST.get('otp')
        session_otp = request.session.get('otp')
        otp_time = request.session.get('otp_time')
        current_time = timezone.now().timestamp()
        # print(user_otp, type(user_otp), 44444444)
        # print(session_otp, type(session_otp), 8888888888)

        if current_time - otp_time > 30:
            error = "OTP has expired. Please request a new one."
            return render(request, 'verify_otp.html', {'error': error})
        # if user_otp and str(user_otp) == str(session_otp):
        if int(user_otp) == session_otp:
            # username = request.session.get('username')  
            first_name = request.session.get('first_name')
            last_name = request.session.get('last_name')
            email = request.session.get('email')
            password = request.session.get('password')
            # phone = request.session.get('phone')
            # profile_image_path = request.session.get('profile_image_path')

            user = CustomUser.objects.create(
                # username=username,
                first_name=first_name,
                last_name=last_name,
                email=email,
                # phone=phone,
                password=make_password(password),
            )
            # if profile_image_path:
            #     Profile.objects.create(user=user, image=profile_image_path)
            # user.save()

            del request.session['otp']
            del request.session['otp_time'] 
            # del request.session['username']
            del request.session['first_name']
            del request.session['last_name']
            del request.session['email']
            del request.session['password']
            # del request.session['phone']
            # del request.session['profile_image_path']
            return redirect('login_page')
        else:
            return HttpResponse("Invalid OTP", status=404)

    return render(request, 'verify_otp.html')


@csrf_protect
def login_page(request):
    # print("324567890-987654")
    if request.method == 'POST':
        # print(111111111111111111)
        email = request.POST.get('email')
        # username = request.POST.get('username')
        password = request.POST.get('password')
        # print(email, password, 5555555555553234)
        user = authenticate(request, email=email, password=password)
        # print(user, 66666666663234)
        # user = CustomUser.objects.filter(username=username).first()

        if user:# Ensure all fields are provided
            login(request, user)
            # print("dsfghjkhgfds")
            return redirect('index')
        else:
            error = "Invalid Credentials"
            return render(request, 'login.html', {'error': error})
    return render(request, 'login.html')

@login_required
def ced_todo(request):
    if request.method == 'POST':
        u = request.user
        title = request.POST['title']
        description = request.POST['description']
        blog_image = request.FILES.get('blog_image')

        if blog_image:
            print("Received image:", blog_image.name)

        todo = ToDo.objects.create(title=title, description=description, user=u, blog_image=blog_image)

        todo.save()
        return redirect('index')
    return render(request, 'ced_todoo.html')

@csrf_protect
@never_cache
@login_required
def index(request):
    u = request.user
    print(u,4444)
    todos = ToDo.objects.filter(user=u).all()
    # todos = ToDo.objects.all()
    print(todos, 5555)
    return render(request, 'dashboard.html', {'todos': todos})

    if request.method == 'POST':        
        print(request.user.id, 333333333)
        title = request.POST['title']
        print("title = ", title)
        description = request.POST['description']
        print("gfdghjkl")
        todo = ToDo.objects.create(title=title, description=description)
        todo.save()
        return redirect('todo_list')
    return render(request, 'dashboard.html', {'todos': todos})

@never_cache
@login_required
def logout_view(request):
    logout(request)
    return redirect('login_page')

# def todo_list(request):
#     todos = ToDo.objects.filter(user=request.user)
#     todos = ToDo.objects.all()
#     return render(request, 'todo_list.html', {'todos': todos})


#  def user_profile(request):
#         if request.method == 'POST':
#             name = request.POST['name']
#             bio = request.POST['bio']
#             gender = request.POST['gender']
#             location = request.POST['location']
#         return render(request, 'user_profile.html')
@login_required
def edit_todo(request, id):
    todo = ToDo.objects.get(id=id)
    print(todo.title, "fdghjkl")
    if request.method == 'POST':
        title = request.POST.get('title')
        description = request.POST.get('description')
        blog_image = request.FILES.get('blog_image')

        todo.title = title
        todo.description = description
        if blog_image:
            todo.blog_image = blog_image
            
        todo.updated_at = datetime.now()
        todo.save()
        return redirect('index')
    return render(request, 'edit_todo.html', {'todo': todo})

@login_required
def delete_todo(request, id):
    todo = get_object_or_404(ToDo, id=id)
    todo.delete()
    return redirect('index')

def resend_otp(request):
    otp = generate_otp()
    send_email(request.session.get('email'), request.session.get('first_name'), otp)
    request.session['otp'] = otp
    request.session['otp_time'] = timezone.now().timestamp()
    return redirect('verify_otp')
    # username = request.session.get('username')
    # email = request.session.get('email')
    # if username and email:
    #     otp = generate_otp()
    #     send_email(email, username, otp)
    #     request.session['otp'] = otp
    #     request.session['otp_time'] = timezone.now().timestamp()
    #     return redirect('verify_otp')
    # else:
    #     return redirect('register_page')

@login_required
def view_todo(request, id):
    todo = ToDo.objects.get(id=id)
    return render(request, 'view_todo.html', {'todo': todo})

@login_required
def others_blog(request):
    user = request.user
    other_users = CustomUser.objects.exclude(id=user.id)
    other_users_todos = ToDo.objects.filter(user__in=other_users)
    return render(request, 'others_blog.html', {'other_users_todos': other_users_todos})

@login_required
def user_profile(request):
    return render(request, 'user_profile.html')

def profile(request):
    return render(request, 'profile.html')

def blog_image(request):
    return render(request, 'blog_image.html')

@login_required
def edit_profile(request):
    if request.method == 'POST':
        # username = request.POST.get('username')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        phone = request.POST.get('phone')
        gender = request.POST.get('gender')
        bio = request.POST.get('bio')
        dob = request.POST.get('dob')
        profile_image = request.FILES.get('profile_image')
        user = request.user
        # user.username = username
        user.first_name = first_name
        user.last_name = last_name
        user.phone = phone
        user.gender = gender
        user.bio = bio
        user.dob = dob
        user.save()
        if profile_image:
            profile = Profile.objects.filter(user=user).first()
            if profile:
                profile.image = profile_image
                profile.save()
            else:
                Profile.objects.create(user=user, image=profile_image)
        
        return redirect('user_profile')
    return render(request, 'edit_profile.html')

@login_required
def premium(request):
    return render(request, 'premium.html')

@login_required
def changepassword(request, token):
    try:
        user = CustomUser.objects.get(forgot_password_token=token)
    except CustomUser.DoesNotExist:
        return HttpResponse("Invalid token", status=400)

    if request.method == "POST":
        new_password = request.POST['new_password']
        confirm_password = request.POST['confirm_password']

        if new_password == confirm_password:
            # Apply the password validator defined in your model
            try:
                # Validate the password according to your custom rules
                password_validator(new_password)
            except ValidationError as e:
                return HttpResponse(f"Password validation failed: {', '.join(e.messages)}", status=400)

            # Update the user's password
            user.password = make_password(new_password)
            user.forgot_password_token = None  # Invalidate the token after use
            user.save()

            # Redirect to a success page or login
            return redirect(reverse('login_page'))
        else:
            return HttpResponse("Passwords do not match", status=400)

    return render(request, 'change_password.html', {'token': token})


def forgotpasswordpage(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        
        if not CustomUser.objects.filter(email=email).exists():
            error = "Email does not exist"
            return render(request, 'forgotpassword.html', {'error': error})
        
        user_obj = CustomUser.objects.get(email=email)
        token = str(uuid.uuid4())
        profile_obj = CustomUser.objects.get(email=email)
        profile_obj.forgot_password_token = token
        profile_obj.save()
        send_forget_password_email(user_obj, token)
        messages.success(request, 'An email has been sent to you with a link to reset your password')
        return redirect('login_page')
    
    return render(request, 'forgotpassword.html')