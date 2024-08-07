from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.tokens import default_token_generator

def send_email(user):
  # token = default_token_generator.make_token(user)
  subject = 'ToDo App'
  message = f'Hi {user.username},You have Successfully created an account'
  email_from = settings.EMAIL_HOST_USER
  recipient_list = [user.email]
  send_mail( subject, message, email_from, recipient_list )