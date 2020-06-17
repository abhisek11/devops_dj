from django.urls import path
from dashboard import views

app_name = 'dashboard'


urlpatterns = [
    path('user/create/', views.DashboardUserCreateView.as_view()),

]
