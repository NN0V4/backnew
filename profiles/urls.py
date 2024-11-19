from django.urls import path 
from . import views


urlpatterns = [
    
    path('login/', views.login_view, name='login'),
    path('signup/', views.signup_view, name='signup'),
    path('confirm_email/<str:token>/<str:email>/', views.confirm_email, name='confirm_email'),  # Email confirmation URL
    path('logout/', views.logout_view, name='logout'),
    path('api/signup/', views.signup_api_view, name='api_signup'),
    path('api/login/', views.login_api_view, name='api_login'),
    
]