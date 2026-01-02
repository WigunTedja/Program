from django.shortcuts import render
from rest_framework import status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authentication import BasicAuthentication
from django.shortcuts import render, redirect
from django.contrib.auth import logout, login, authenticate
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.models import User
from django.contrib import messages

# --- API VIEW ---
def index(request):
    return render(request, 'pages/index.html')

def login_view(request):
    # Jika user sudah login, redirect
    if request.user.is_authenticated:
        if request.user.is_staff:
            return redirect('admin-bank-dashboard') # Atau halaman admin kamu
        return redirect('bank-dashboard') # Halaman dashboard nasabah

    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)

            if user is not None:
                login(request, user)
                # LOGIC REDIRECTION:
                if user.is_staff:
                    return redirect('admin-bank-dashboard') 
                else:
                    return redirect('bank-dashboard')
            else:
                messages.error(request, "Username atau password salah.")
        else:
            messages.error(request, "Username atau password salah.")
    else:
        form = AuthenticationForm()

    return render(request, 'pages/login.html', {'form': form})

def logout_view(request):
    logout(request)
    # Dengan memanggil get_messages dan mengiterasinya, 
    # Django menganggap pesan sudah "dibaca" dan menghapusnya dari antrian.
    storage = messages.get_messages(request)
    for message in storage:
        pass # Kita tidak melakukan apa-apa, cuma biar dianggap sudah dibaca.
    # Setelah logout, arahkan kembali ke halaman login atau halaman welcome
    return redirect('login')