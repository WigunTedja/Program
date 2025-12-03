from django.urls import path
from .views import UserRegisterView, DepositView, index

urlpatterns = [
    path('', index, name='index'),
    path('auth/register/', UserRegisterView.as_view(), name='user-register'),
    path('account/deposit/', DepositView.as_view(), name='account-deposit'),
]