from django.db import models
from django.contrib.auth.models import PermissionsMixin
from django.contrib.auth.base_user import AbstractBaseUser
from .userManager import CustomUserManager

# Create your models here.
class User(AbstractBaseUser, PermissionsMixin):
	"""Custome user model for role based authentication."""

	class Meta:
		verbose_name = 'user'
		verbose_name_plural = 'users'


	# role fields
	ADMIN = 1
	SOLUTION_PROVIDER = 2
	SOLUTION_SEEKER = 3

	ROLE_CHOICES = [
	    [ADMIN, 'Admin'],
	    [SOLUTION_PROVIDER, 'Solution Provider'],
	    [SOLUTION_SEEKER, 'Solution Seeker']
	]

	username = models.CharField(max_length=20, unique=True)
	password = models.CharField(max_length=200)
	email = models.EmailField(blank=True)
	first_name = models.CharField(max_length=30, blank=True)
	last_name = models.CharField(max_length=50, blank=True)
	phone_no = models.BigIntegerField(null=True, blank=True)
	otp = models.CharField(max_length=4, blank=True, null=True, default=None)
	user_role = models.PositiveSmallIntegerField(choices=ROLE_CHOICES)
	is_superuser = models.BooleanField(default=True, blank=True)
	is_staff = models.BooleanField(default=True, blank=True)
	created_date = models.DateTimeField(auto_now_add=True)

	USERNAME_FIELD = 'username'

	REQUIRED_FIELD = []

	objects = CustomUserManager()

	def __str__(self):
		return self.username