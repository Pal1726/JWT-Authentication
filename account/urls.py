
from django.urls import path
from account.views import UserRegistrationView,UserLoginView,UserProfileView,UserChangePasswordView,SendPasswordResetEmailView,UserPasswordResetView,CustomTokenRefreshView
from rest_framework_simplejwt import views as jwt_views
urlpatterns = [
    path('', UserRegistrationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('changepassword/', UserChangePasswordView.as_view(), name='changepassword'),
    path('send-reset-password-email/', SendPasswordResetEmailView.as_view(), name='send-reset-password-email'),
    path('reset-password/<uid>/<token>/', UserPasswordResetView.as_view(), name='reset-password'),
    # path('api/token/refresh/',jwt_views.TokenRefreshView.as_view(),name='token_refresh')   #inbuilt refresh token generate
    path('api/token/refresh/', CustomTokenRefreshView.as_view(), name='custom_token_refresh'),  #custom done

    
]