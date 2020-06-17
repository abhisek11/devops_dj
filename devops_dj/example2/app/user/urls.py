from django.urls import path
from user.knox_views import views as _views
from user import views


app_name = 'user'

urlpatterns = [
    path('signup/', views.CreateUserView.as_view(), name='create'),
    path('domain_add/', views.DomainAddGetView.as_view(), name='domain_add'),
    path(
        'domain_update/<pk>/',
        views.EditDomainView.as_view(),
        name='domain_update'
        ),
    path(
        'email/verify/',
        views.EmailForgotPassword.as_view(),
        name='generate_otp'
        ),
    path('activate/<uidb64>/<token>/', views.activate, name='activate'),
    path('profile/', views.ProfileView.as_view()),
    path('profile_update/<pk>/', views.EditProfileView.as_view()),
    path('token/', views.CreateTokenView.as_view(), name='token'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', _views.LogoutView.as_view(), name='logout'),
    path('logoutall/', _views.LogoutAllView.as_view(), name='logoutall'),
    path('change_password/', views.ChangePasswordView.as_view()),
    path('forgot_password/', views.ForgotPasswordView.as_view()),

]
