from rest_framework import permissions
from .models import User

# custom permissions
class IsAdmin(permissions.BasePermission):
	"""
		Admin user permissions.
	"""

	def has_permission(self, request, view):
		return True if request.user.user_role == User.ADMIN else False


class SolutionProvider(permissions.BasePermission):
	"""
		Solution Provider user permissions.
	"""

	def has_permission(self, request, view):
		return True if request.user.user_role == User.SOLUTION_PROVIDER else False


class SolutionSeeker(permissions.BasePermission):
	"""
		Solution Seeker user permissions.
	"""

	def has_permission(self, request, view):
		return True if request.user.user_role == User.SOLUTION_SEEKER else False			