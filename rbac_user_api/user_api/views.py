from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status, viewsets
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from .serializer import UserRegistrationSerializer, UserLoginSerializer, ChangePasswordSerializer
from .models import User
from .userPermission import IsAdmin, SolutionProvider, SolutionSeeker

# Create your views here.
class home(APIView):
	"""
		Demo url.
	"""
	def get(self, request):
		return Response({"msg": "Hello"})


class UserViewSet(viewsets.ModelViewSet):
	"""User view for get and create user.

		is_superuser is set to false because we don't want 
		to show superuser data.
	"""

	queryset = User.objects.all()
	serializer_class = UserRegistrationSerializer
	http_method_names = ['get', 'post']


class ReadUpdateDeleteUserViewSet(viewsets.ModelViewSet):
	"""
		get specific User data, update and delete.
		if user authenticated and authorized. 
	"""

	authentication_classes = [JWTAuthentication]
	permission_classes = [IsAuthenticated]

	queryset = User.objects.filter(is_superuser=False)
	serializer_class = UserRegistrationSerializer
	http_method_names = ['get', 'patch', 'delete']

	def partial_update(self, request, pk=None):
		"""
			User profile update.
		"""
		try:
			user_object = User.objects.get(pk=pk)
			user_serializer = self.serializer_class(user_object, data=request.data, partial=True)
			
			if user_serializer.is_valid():
				user_serializer.save()
				return Response({"success": True, "message": "User updated.", "data": user_serializer.data}, status=status.HTTP_200_OK)

			return Response({"success": False, "message": user_serializer.errors}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

		except User.DoesNotExist:
			return Response({"success": False, "message": "User not found."}, status=status.HTTP_404_NOT_FOUND)

	def retrieve(self, request, pk=None):
		"""
			Get specific user.
		"""
		try:
			user_object = User.objects.get(pk=pk)
			return Response({"success": True, "message": "User found.", "data": self.serializer_class(user_object).data}, status=status.HTTP_200_OK)

		except User.DoesNotExist:
			return Response({"success": False, "message": "User not found."}, status=status.HTTP_404_NOT_FOUND)

	def destroy(self, request, pk=None):
		"""
			Delete specific user.
		"""
		try:
			user_object = User.objects.get(pk=pk).delete()
			return Response({"success": True, "message": "User Deleted."}, status=status.HTTP_200_OK)

		except User.DoesNotExist:
			return Response({"success": False, "message": "User not found."}, status=status.HTTP_404_NOT_FOUND)


class UserLoginViewSet(APIView):
    """
		User login view set for authentication and
		getting access token.
    """

    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        auth_user = serializer.is_valid(raise_exception=True)

        if auth_user:

            response = {
                'success': True,
                'message': 'User logged in successfully',
                'otp': serializer.data['otp'],
                'access': serializer.data['access_token'],
                'refresh': serializer.data['refresh_token'],
                'message': serializer.data['message'],
                'url': serializer.data['url']
            }

            return Response(response, status=status.HTTP_200_OK)

        return Response({'success': False, 'message': serializer.errors}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class VerifyOTPViewSet(APIView):
	"""
		OTP verification with authentication permission.
	"""

	authentication_classes = [JWTAuthentication]
	permission_classes = [IsAuthenticated]

	def get(self, request, otp):
		"""
			Check for otp with token.
		"""
        
		try:
		    auth_user = User.objects.get(pk=request.user.id)
		    auth_user_otp = auth_user.otp

		    if int(auth_user_otp) == otp:
		        response = {
		            'success': True,
		            'message': 'User OTP verified.',
		        }

		        return Response(response, status=status.HTTP_200_OK)

		    else:
		    	response = {
                                'success': False,
                                'message': 'User OTP invalid.',
                        }

		    	return Response(response, status=status.HTTP_404_NOT_FOUND)

		except User.DoesNotExist:
			return Response({'success': False, 'message': 'User may not found.'}, status=status.HTTP_404_NOT_FOUND)


class ChangePasswordViewset(APIView):
	"""
		User password change view if user is authenticated with old password
		then password can be changed.
	"""

	authentication_classes = [JWTAuthentication]
	permission_classes = [IsAuthenticated]

	def patch(self, request):
		"""
			Password change update method for user.
		"""
		user_data = request.data
		user_data["username"] = request.user.username

		user_serializer = ChangePasswordSerializer(data=user_data)

		if user_serializer.is_valid():
			user_serializer.save()

			return Response({"success": True, "message": "password changed."})

		return Response({"success": False, "message": user_serializer.errors})
