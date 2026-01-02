from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='dashboard'),
    path('login/', views.login_view, name='login'),
    #path('account/deposit/', DepositView.as_view(), name='account-deposit'),
    path('logout/', views.logout_view, name='logout'),
    # path('bank/')
]