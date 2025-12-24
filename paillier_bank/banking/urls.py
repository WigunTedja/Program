from django.urls import path
from . import views

urlpatterns = [
    
    path('dashboard/', views.dashboard, name='dashboard'),
    path('saldo/', views.lihat_saldo, name='lihat_saldo'),
    path('transfer/', views.transfer_saldo, name='transfer_saldo'),
]