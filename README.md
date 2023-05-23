# rbac_user_api

In this task, i have tried to meet all of your requirements within a time. But i found some difficulty to implement forgot password via email and actual otp send to user's mobile number. These two features i have failed to implement within a timeline.


# RBAC

1) here three role has been defined and based on role, permission classes are created inside app.
2) I have created custom user model by inheriting abstractbaseuser class to implement role and custom permission.
3) JWT authentication is implemented and OTP also. If user is authenticated by their username and password, token will be returned and then user otp need to be verified by adding token in header of API.
4) All the APIs, which has a role to modify a data, needs authorization in header because if user is authenticated then only they can change data.
5) Permissions are implemented for Admin, Solution Provider and Solution Seeker and these permission classes are used as a permission_class for role based operation.
6) I have attached a Postman collection with API names.
