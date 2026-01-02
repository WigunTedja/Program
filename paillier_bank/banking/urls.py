from django.urls import path
from . import views

urlpatterns = [
    path('admin-dashboard', views.admin_dashboard, name='admin-bank-dashboard'),
    path('daftar-nasabah/', views.admin_register_nasabah_page, name='admin-register-nasabah'),
    path('admin-setor-tunai/', views.admin_setor_tunai, name='admin-setor-tunai'),
    path('admin-tarik-tunai/', views.admin_tarik_tunai, name='admin-tarik-tunai'),
    
    path('dashboard/', views.dashboard, name='bank-dashboard'),
    path('saldo/', views.lihat_saldo, name='lihat-saldo'),
    path('transfer/', views.transfer_saldo, name='transfer-saldo'),
]