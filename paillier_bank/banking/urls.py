from django.urls import path
from . import views

urlpatterns = [
    
    path('dashboard/', views.dashboard, name='bank-dashboard'),
    path('saldo/', views.lihat_saldo, name='lihat-saldo'),
    path('transfer/', views.transfer_saldo, name='transfer-saldo'),
]