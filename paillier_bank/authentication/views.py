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
from django.db import transaction
from .models import Nasabah
from .serializers import NasabahSerializer

# Library Kriptografi & Helper
import json
import os
import base64
import hashlib
from phe import paillier
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- FUNGSI HELPER (Untuk Enkripsi Private Key) ---

def generate_aes_key_from_pin(pin, salt):
    """Mengubah PIN + Salt menjadi Kunci AES 32-byte"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(pin.encode()))

def encrypt_private_key(private_key_obj, pin):
    """Enkripsi Private Key Paillier menggunakan PIN"""
    # 1. Serialisasi Private Key ke JSON
    priv_data = {
        'p': private_key_obj.p,
        'q': private_key_obj.q,
        'n': private_key_obj.public_key.n
    }
    priv_json = json.dumps(priv_data)
    
    # 2. Generate Salt dan Kunci AES
    salt = os.urandom(16)
    key = generate_aes_key_from_pin(pin, salt)
    
    # 3. Enkripsi
    f = Fernet(key)
    encrypted_blob = f.encrypt(priv_json.encode())
    
    return salt.hex(), encrypted_blob.decode()

# --- API VIEW ---

def index(request):
    return render(request, 'pages/index.html')

class RegisterNasabahView(APIView):
    """
    Endpoint untuk mendaftarkan nasabah baru.
    Hanya bisa diakses oleh Staff/Admin via Postman/API.
    """
    # Menggunakan Basic Auth agar Postman bisa akses tanpa CSRF Token
    authentication_classes = [BasicAuthentication]
    permission_classes = [permissions.IsAdminUser] 

    def post(self, request):
        data = request.data
        
        # 1. Validasi Input
        required = ['username', 'password', 'nama_lengkap', 'pin']
        for field in required:
            if field not in data:
                return Response({"error": f"Field {field} wajib diisi"}, status=status.HTTP_400_BAD_REQUEST)

        username = data['username']
        password = data['password']
        nama_lengkap = data['nama_lengkap']
        pin = data['pin']

        # Validasi sederhana
        if User.objects.filter(username=username).exists():
            return Response({"error": "Username sudah digunakan"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            with transaction.atomic():
                # 2. Buat User Django
                user = User.objects.create_user(username=username, password=password)

                # 3. Generate Keypair Paillier (Logic Inti)
                # n_length=1024 cukup untuk development
                public_key, private_key = paillier.generate_paillier_keypair(n_length=1024)

                # 4. Amankan Private Key dengan PIN Nasabah
                salt_hex, encrypted_priv_key = encrypt_private_key(private_key, pin)

                # 5. Buat Saldo Awal "0" terenkripsi
                encrypted_saldo_obj = public_key.encrypt(0)
                encrypted_saldo_str = str(encrypted_saldo_obj.ciphertext())

                # 6. Hash PIN (untuk login cepat)
                pin_hash = hashlib.sha256(pin.encode()).hexdigest()

                # 7. Simpan ke Database Nasabah
                nasabah = Nasabah.objects.create(
                    user=user,
                    nama_lengkap=nama_lengkap,
                    pub_key_n=str(public_key.n),
                    pub_key_g=str(public_key.g),
                    priv_pail_key=encrypted_priv_key,
                    key_salt=salt_hex,
                    pin_hash=pin_hash,
                    encrypted_saldo=encrypted_saldo_str
                )
                # Return Data
                serializer = NasabahSerializer(nasabah)
                return Response({
                    "message": "Registrasi Nasabah Berhasil",
                    "data": serializer.data
                }, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
def is_admin(user):
    return user.is_authenticated and user.is_staff

@login_required(login_url='/auth/login/') # Pastikan sudah login
@user_passes_test(is_admin) # Pastikan user adalah Staff/Admin
def admin_register_nasabah_page(request):
    if request.method == 'POST':
        # Ambil data dari Form HTML
        nama_lengkap = request.POST.get('nama_lengkap')
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password') # Password untuk Login Akun
        pin = request.POST.get('pin') # PIN untuk Kriptografi

        # 1. Validasi Sederhana
        if User.objects.filter(username=username).exists():
            messages.error(request, "Username/Email sudah digunakan!")
            return render(request, 'pages/admin_register_nasabah.html')

        try:
            with transaction.atomic():
                # 2. Buat User Django
                user = User.objects.create_user(username=username, email=email, password=password)

                # 3. Generate Keypair Paillier (PERINGATAN: INI BERAT/LAMBAT)
                # Browser akan loading lama di sini.
                public_key, private_key = paillier.generate_paillier_keypair(n_length=1024)

                # 4. Enkripsi Private Key dengan PIN
                salt_hex, encrypted_priv_key = encrypt_private_key(private_key, pin)

                # 5. Buat Saldo Awal terenkripsi
                encrypted_saldo_obj = public_key.encrypt(100000)
                encrypted_saldo_str = str(encrypted_saldo_obj.ciphertext())

                # 6. Hash PIN
                pin_hash = hashlib.sha256(pin.encode()).hexdigest()

                # 7. Simpan Nasabah
                Nasabah.objects.create(
                    user=user,
                    nama_lengkap=nama_lengkap,
                    pub_key_n=str(public_key.n),
                    pub_key_g=str(public_key.g),
                    priv_pail_key=encrypted_priv_key,
                    key_salt=salt_hex,
                    pin_hash=pin_hash,
                    encrypted_saldo=encrypted_saldo_str
                )

                messages.success(request, f"Sukses! Nasabah {nama_lengkap} berhasil didaftarkan dengan Kunci Homomorfik.")
                return redirect('admin-register-nasabah')

        except Exception as e:
            messages.error(request, f"Terjadi Kesalahan Sistem: {str(e)}")
            return render(request, 'pages/admin_register_nasabah.html')

    # Jika GET, tampilkan form kosong
    return render(request, 'pages/admin_register_nasabah.html')

def login_view(request):
    # Jika user sudah login, langsung lempar ke halaman yang sesuai
    if request.user.is_authenticated:
        if request.user.is_staff:
            return redirect('dashboard') # Atau halaman admin kamu
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
                # Jika Admin -> arahkan ke welcome page (atau admin dashboard)
                # Jika Nasabah -> arahkan ke dashboard
                if user.is_staff:
                    return redirect('dashboard') # Ganti dengan nama URL halaman welcome kamu
                else:
                    return redirect('bank-dashboard') # Pastikan URL name 'dashboard' sudah ada
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