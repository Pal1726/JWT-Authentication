from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from account.serializers import UserRegistrationSerializer,UserLoginSerializer,UserProfileSerializer,UserChangePasswordSerializer,SendPasswordResetEmailSerializer,UserPasswordResetSerializer
from django.contrib.auth import authenticate
from account.renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated,AllowAny
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

class UserLoginView(APIView):
	# renderer_classes = [UserRenderer]
	def post(self,request,format=None):
		serializer=UserLoginSerializer(data=request.data)
		if serializer.is_valid(raise_exception=True):
			email=serializer.data.get('email')
			password=serializer.data.get('password')
			user=authenticate(email=email,password=password)
			if user is not None:
				token = get_tokens_for_user(user)
				return Response({'token':token,'msg':'login Successful'}, status=status.HTTP_200_OK)
			else:
				return Response({'errors':{'non_field_errors':['email or passwrod is not valid' ]}},status=status.HTTP_404_NOT_FOUND)
		return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)	

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