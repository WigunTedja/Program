from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('register/', views.registrasi_nasabah, name='register'),
    path('login/', views.login_nasabah, name='login')
    #path('account/deposit/', DepositView.as_view(), name='account-deposit'),
]