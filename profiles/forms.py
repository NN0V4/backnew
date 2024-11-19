from django import forms
from django.core.exceptions import ValidationError
import re
 

class UniversitySignUpForm(forms.Form):
    email = forms.EmailField(label="University Email", max_length=255)
    password = forms.CharField(widget=forms.PasswordInput, label="Password")

    def clean_password(self):
        password = self.cleaned_data.get("password")

        if len(password) < 8:
            raise ValidationError("Password must be at least 8 characters long.")
        
        # Example: Check for at least one uppercase letter, one lowercase letter, and one number
        if (not re.search(r"[A-Z]", password) or
         not re.search(r"[a-z]", password) or
         not re.search(r"[0-9]", password) or
         not re.search(r"[!@#$%-_&*()?:{}|<>]", password)):
          raise ValidationError("Password must contain at least one uppercase letter, lowercase letter,numbers and special characters")
        
        return password
    
    def clean_email(self):
        email = self.cleaned_data.get("email")
        if not email.endswith("@cit.just.edu.jo"):  # Replace with your actual university domain
            raise ValidationError("Please enter a valid university email.")
        
        return email

                     

class UniversityLoginForm(forms.Form):
    email = forms.EmailField(label="University Email", max_length=255)
    password = forms.CharField(widget=forms.PasswordInput, label="Password")

    def clean_email(self):
        email = self.cleaned_data.get("email")
        if not email.endswith("@cit.just.edu.jo"):  # Replace with your actual university domain
            raise ValidationError("Please use a valid university email.")
        return email
        



