from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='dashboard'),
    path('register/', views.RegisterNasabahView.as_view(), name='register'),
    path('admin/register-nasabah/', views.admin_register_nasabah_page, name='admin-register-nasabah'),
    path('login/', views.login_view, name='login'),
    #path('account/deposit/', DepositView.as_view(), name='account-deposit'),
    path('logout/', views.logout_view, name='logout'),
]