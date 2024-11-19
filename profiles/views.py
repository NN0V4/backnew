import uuid
from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect
from .forms import UniversitySignUpForm, UniversityLoginForm
from django.contrib.auth.models import User
from django.contrib import messages  
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils import timezone
from django.urls import reverse
from django.contrib.auth import logout
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from django.core.exceptions import ValidationError
import logging
from rest_framework.permissions import AllowAny
from .serializers import UserSerializer
logger = logging.getLogger(__name__)







def signup_view(request):
    form = UniversitySignUpForm(request.POST or None)
    
    if request.method == 'POST' and form.is_valid():
        email = form.cleaned_data['email']
        password = form.cleaned_data['password']

        if User.objects.filter(username=email).exists():
            # User already registered case
            messages.error(request, "This email is already registered.")
        else:
            # Create and save the user if not registered
            user = User.objects.create_user(username=email, email=email, password=password)
            user.is_active = True  # Directly set user as active
            user.save()


            token = str(uuid.uuid4())
            user.profile.verification_token = token
            user.profile.verification_sent_at = timezone.now()
            user.profile.save() 

            # Prepare email content using `email.html`
            confirmation_link = request.build_absolute_uri(reverse('confirm_email', args=[token, email]))
            email_content = render_to_string('profiles/email.html', {'confirmation_link': confirmation_link}) 


            send_mail(
            subject='Email Confirmation',
            message='',
            from_email='ctfzone99@gmail.com',
            recipient_list=[email],
            html_message=email_content ) # Use `email.html` for the email template
            
            messages.success(request, 'Verification email sent! Please check your inbox.')
            return redirect('signup')  

    return render(request, 'profiles/signup.html', {'form': form})



@api_view(['POST'])
@permission_classes([AllowAny])  
def signup_api_view(request):
    logger.debug(f"Headers: {request.headers}")
    logger.debug(f"Data: {request.data}")

    if request.method == 'POST':
        # Use the form to validate email and password
        form = UniversitySignUpForm(request.data)

        if not form.is_valid():
            # If the form is not valid, return the errors as response
            return Response(form.errors, status=status.HTTP_400_BAD_REQUEST)

        # If the form is valid, process the user creation
        email = form.cleaned_data['email']
        password = form.cleaned_data['password']

        # Check if the email already exists
        if User.objects.filter(username=email).exists():
            return Response({"error": "This email is already registered."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Create and save the user
            user = User.objects.create_user(username=email, email=email, password=password)
            user.is_active = False  # Set the user as inactive until email is confirmed
            user.save()

            # Generate the verification token
            token = str(uuid.uuid4())
            # Assuming 'profile' is a custom model related to User
            user.profile.verification_token = token
            user.profile.verification_sent_at = timezone.now()
            user.profile.save()

            # Prepare email content
            confirmation_link = request.build_absolute_uri(reverse('confirm_email', args=[token, email]))
            email_content = render_to_string('profiles/email.html', {'confirmation_link': confirmation_link})

            # Send the verification email
            send_mail(
                subject='Email Confirmation',
                message='',
                from_email='ctfzone99@gmail.com',
                recipient_list=[email],
                html_message=email_content
            )

            return Response({"message": "Verification email sent! Please check your inbox."}, status=status.HTTP_201_CREATED)

        except Exception as e:
            # Log the exception and return an error response
            logger.error(f"Error occurred during signup: {str(e)}")
            return Response({"error": "An error occurred during signup. Please try again."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)





def logout_view(request):
    logout(request)
    return redirect('home')  # Redirect to login or homepage after logout







def confirm_email(request, token, email):
    try:
        user = User.objects.get(email=email)
        if user.profile.verification_token == token:
            user.is_active = True
            user.save()
            user.profile.verification_token = None
            user.profile.save()
            messages.success(request, 'Your email has been confirmed.')
            return redirect('home')
        else:
            messages.error(request, 'Invalid confirmation link.')
    except User.DoesNotExist:
        messages.error(request, 'Invalid confirmation link.')
    return redirect('signup')






def login_view(request):
    """
    Handles user login via the web form.
    """
    form = UniversityLoginForm(request.POST or None)

    if request.method == 'POST' and form.is_valid():
        email = form.cleaned_data['email']
        password = form.cleaned_data['password']

        try:
            user = User.objects.get(email=email)
            if not user.is_active:
                # Prevent login if the user's email is not confirmed
                messages.error(request, "Your account is not active. Please confirm your email.")
                return render(request, 'profiles/login.html', {'form': form})

            # Authenticate the user
            user_auth = authenticate(request, username=user.username, password=password)
            if user_auth is not None:
                # Successful login
                login(request, user_auth)
                return redirect('home')  # Redirect to homepage after successful login
            else:
                # Invalid password
                messages.error(request, "Invalid email or password.")

        except User.DoesNotExist:
            # User does not exist
            messages.error(request, "No account with this email exists.")

    # Keep the user on the login page if there’s an error
    return render(request, 'profiles/login.html', {'form': form})


@api_view(['POST'])
@permission_classes([AllowAny])  # Allow access without authentication
def login_api_view(request):
    """
    Handles user login via API.
    """
    if request.method == 'POST':
        email = request.data.get('email')
        password = request.data.get('password')

        try:
            # Fetch the user by email
            user = User.objects.get(email=email)

            if not user.is_active:
                return Response({"error": "Your account is not active. Please confirm your email."},
                                status=status.HTTP_403_FORBIDDEN)

            # Authenticate the user
            user_auth = authenticate(request, username=user.username, password=password)
            if user_auth is not None:
                # Login the user and return success
                login(request, user_auth)
                return Response({"message": "Login successful!" , "redirect_url": "home"}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Invalid email or password."}, status=status.HTTP_400_BAD_REQUEST)

        except User.DoesNotExist:
            return Response({"error": "No account with this email exists."}, status=status.HTTP_404_NOT_FOUND)

    return Response({"error": "Invalid request method."}, status=status.HTTP_405_METHOD_NOT_ALLOWED)





