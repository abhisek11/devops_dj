from django.urls import path
from user.knox_views import views as _views
from user import views


app_name = 'user'

urlpatterns = [
    path('signup/', views.CreateUserView.as_view(), name='create'),
    path('tenant_add/', views.TenantAddGetView.as_view(), name='tenant_add'),
    path(
        'tenant_update/<pk>/',
        views.EditTenantView.as_view(),
        name='tenant_add'
        ),
    path('profile/', views.ProfileView.as_view()),
    path('profile_update/<pk>/', views.EditProfileView.as_view()),
    path('token/', views.CreateTokenView.as_view(), name='token'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', _views.LogoutView.as_view(), name='logout'),
    path('logoutall/', _views.LogoutAllView.as_view(), name='logoutall'),
    path('change_password/', views.ChangePasswordView.as_view()),
    path('forgot_password/', views.ForgotPasswordView.as_view()),

]
