from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from account.serializers import UserRegistrationSerializer,UserLoginSerializer,UserProfileSerializer,UserChangePasswordSerializer,SendPasswordResetEmailSerializer,UserPasswordResetSerializer
from django.contrib.auth import authenticate
from account.renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated,AllowAny
from django.utils import timezone

from django.utils.timezone import now

from datetime import timedelta
from account.models import User

# Generate Token Manually
def get_tokens_for_user(user):
  	refresh = RefreshToken.for_user(user)
  	return {
      'refresh': str(refresh),
      'access': str(refresh.access_token),
  	}

# class UserRegistrationView(APIView):
# 	def post(self,request,format=None):
# 		return Response({'msg':'Registration Successful'})

class CustomTokenRefreshView(APIView):
    permission_classes = [AllowAny]   # Allow all users to refresh tokens ,you can use IsAuthenticated also

    def post(self, request, *args, **kwargs):
        refresh_token = request.data.get('refresh')
        
        if not refresh_token:
            return Response({'error': 'Refresh token is required'}, status=400)

        try:
            refresh = RefreshToken(refresh_token)
            new_access_token = str(refresh.access_token)
            return Response({'access': new_access_token})
        
        except Exception as e:
            return Response({'error': 'Invalid refresh token'}, status=400)

# Create your views here
class UserRegistrationView(APIView):
	# renderer_classes = [UserRenderer]
	def post(self,request,format=None):
		serializer=UserRegistrationSerializer(data=request.data)
		if serializer.is_valid(raise_exception=True):
			user=serializer.save()
			token = get_tokens_for_user(user)	
			return Response({'token':token,'msg':'Registration Successful'},
			status=status.HTTP_201_CREATED)

		return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

# class UserRegistrationView(APIView):
#     def post(self, request, format=None):
#         serializer = UserRegistrationSerializer(data=request.data)
#         if serializer.is_valid(raise_exception=True):
#             user=serializer.save()
#             return Response({'msg': 'Registration successful. Please verify your email.'}, status=status.HTTP_201_CREATED)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# class UserLoginView(APIView):
# 	# renderer_classes = [UserRenderer]
# 	def post(self,request,format=None):
# 		serializer=UserLoginSerializer(data=request.data)
# 		if serializer.is_valid(raise_exception=True):
# 			email=serializer.data.get('email')
# 			password=serializer.data.get('password')
# 			user=authenticate(email=email,password=password)
# 			if user is not None:
# 				token = get_tokens_for_user(user)
# 				return Response({'token':token,'msg':'login Successful'}, status=status.HTTP_200_OK)
# 			else:
# 				return Response({'errors':{'non_field_errors':['email or passwrod is not valid' ]}},status=status.HTTP_404_NOT_FOUND)
# 		return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)	

      



class UserLoginView(APIView):
    def post(self, request, format=None):
        # Print the incoming request data for debugging
        print("Request data:", request.data)

        # Create an instance of the serializer and validate the data
        serializer = UserLoginSerializer(data=request.data)

        # Check if serializer is valid and raise exceptions if not
        if serializer.is_valid(raise_exception=True):
            email = serializer.validated_data.get('email')
            password = serializer.validated_data.get('password')

            print(f"Trying to authenticate user: {email}")

            # Try to get the user by email
            try:
                user = User.objects.get(email=email)

                # Check if user is blocked and if 15 minutes have passed since the last failed login
                if user.is_blocked:
                    # If more than 15 minutes have passed, unblock the user and reset failed attempts
                    if user.last_failed_login and timezone.now() - user.last_failed_login > timedelta(minutes=15):
                        user.is_blocked = False
                        user.failed_attempts = 0
                        user.save()
                    else:
                        return Response({'errors': {'non_field_errors': ['Your account is blocked due to multiple failed login attempts. Try again later.']}},
                                        status=status.HTTP_403_FORBIDDEN)

                # Authenticate the user using the email and password provided
                user_authenticated = authenticate(request=request, email=email, password=password)
                print('give me details',user_authenticated)

                if user_authenticated:
                    print(f"User authenticated: {user.email}")  

                    # Reset failed login attempts and unblock the user on successful login
                    user.failed_attempts = 0
                    user.is_blocked = False
                    user.save()

                    # Generate token for the authenticated user
                    token = get_tokens_for_user(user)

                    return Response({'token': token, 'msg': 'Login Successful'}, status=status.HTTP_200_OK)

                else:
                    print("Authentication failed.")  

                    # If authentication fails, increment failed attempts and block user if needed
                    user.failed_attempts += 1
                    user.last_failed_login = timezone.now()

                    if user.failed_attempts >= 3:
                        user.is_blocked = True
                    user.save()

                    return Response({'errors': {'non_field_errors': ['Invalid email or password.']}},
                                    status=status.HTTP_404_NOT_FOUND)

            except User.DoesNotExist:
                print(f"User with email {email} does not exist.")  
                return Response({'errors': {'non_field_errors': ['User does not exist. First, register yourself.']}},
                                status=status.HTTP_404_NOT_FOUND)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserProfileView(APIView):

  	# renderer_classes = [UserRenderer]
  	permission_classes = [IsAuthenticated]
  	def get(self, request, format=None):
  		serializer = UserProfileSerializer(request.user)
  		return Response(serializer.data, status=status.HTTP_200_OK)

class UserChangePasswordView(APIView):
  	# renderer_classes = [UserRenderer]
  	permission_classes = [IsAuthenticated]
  	def post(self, request, format=None):
  	  	serializer = UserChangePasswordSerializer(data=request.data, context={'user':request.user})
  	  	serializer.is_valid(raise_exception=True)
  	  	return Response({'msg':'Password Changed Successfully'}, status=status.HTTP_200_OK)


class SendPasswordResetEmailView(APIView):
	# renderer_classes = [UserRenderer]
  	def post(self, request, format=None):
  		serializer = SendPasswordResetEmailSerializer(data=request.data)
  		serializer.is_valid(raise_exception=True)
  		return Response({'msg':'Password Reset link send. Please check your Email'}, status=status.HTTP_200_OK)


class UserPasswordResetView(APIView):
  	# renderer_classes = [UserRenderer]
  	def post(self, request, uid, token, format=None):
  		serializer = UserPasswordResetSerializer(data=request.data, context={'uid':uid, 'token':token})
  		serializer.is_valid(raise_exception=True)
  		return Response({'msg':'Password Reset Successfully'}, status=status.HTTP_200_OK)