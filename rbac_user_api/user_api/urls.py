from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenVerifyView
from .views import *

router = DefaultRouter()
router.register('users', UserViewSet, basename='user')
router.register('user/operation', ReadUpdateDeleteUserViewSet, basename='user_operation')

urlpatterns = [
    path('', home.as_view()),
    path('token', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh', TokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify', TokenVerifyView.as_view(), name='token_verify'),
    path('login', UserLoginViewSet.as_view(), name='user_login'),
    path('verify_otp/<int:otp>', VerifyOTPViewSet.as_view(), name='verify_otp'),
    path('change_password', ChangePasswordViewset.as_view(), name='user_login'),
] + router.urls
