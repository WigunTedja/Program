# views.py
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import User
from django.contrib import messages
from django.db import transaction
from authentication.models import Nasabah
from django.http import HttpResponse
import hashlib
from phe import paillier
from .utils import decrypt_private_key, encrypt_private_key


@login_required(login_url='login')
def dashboard(request):
    """
    Halaman utama setelah nasabah login.
    Menampilkan menu navigasi utama.
    """
    context = {
        'user': request.user, # Mengirim data user ke template
    }
    return render(request, 'pages/bank_dashboard.html', context)

@login_required(login_url='login')
def admin_dashboard(request):
    """
    Halaman utama setelah admin  login.
    Menampilkan menu navigasi utama.
    """
    context = {
        'user': request.user, # Mengirim data user ke template
    }
    return render(request, 'pages/admin_bank_dashboard.html', context)


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

@login_required(login_url='login')
def lihat_saldo(request):
    """
    View untuk melihat saldo terdekripsi.
    Membutuhkan input PIN dari user setiap kali diakses (Session-less encryption).
    """
    nasabah = request.user.nasabah # Mengakses via related_name
    saldo_plain = None
    error_msg = None

    if request.method == 'POST':
        pin_input = request.POST.get('pin')

        # 1. Verifikasi Hash PIN (Cepat, hemat resource CPU sebelum dekripsi berat)
        input_hash = hashlib.sha256(pin_input.encode()).hexdigest()
        
        if input_hash != nasabah.pin_hash:
            messages.error(request, "PIN Salah!")
        else:
            try:
                # 2. Dekripsi Private Key Paillier (Berat)
                private_key = decrypt_private_key(
                    encrypted_blob_str=nasabah.priv_pail_key,
                    pin=pin_input,
                    salt_hex=nasabah.key_salt,
                    pub_n=nasabah.pub_key_n
                )

                # 3. Dekripsi Saldo
                # Saldo di DB tersimpan sebagai String angka ciphertext
                encrypted_saldo_int = int(nasabah.encrypted_saldo)
                
                # Bungkus kembali menjadi EncryptedNumber agar bisa didekripsi library phe
                enc_saldo_obj = paillier.EncryptedNumber(private_key.public_key, encrypted_saldo_int)
                
                # DO THE MAGIC: Dekripsi Homomorfik
                saldo_plain = private_key.decrypt(enc_saldo_obj)
                
                messages.success(request, "Saldo berhasil didekripsi.")
                
            except Exception as e:
                error_msg = f"Error Dekripsi: {str(e)}"
                messages.error(request, error_msg)

    return render(request, 'pages/lihat_saldo.html', {
        'nasabah': nasabah,
        'saldo': saldo_plain
    })

@login_required(login_url='login')
def transfer_saldo(request):
    # TODO: Nanti di sini form transfer -> homomorphic addition -> update DB
    return HttpResponse("<h3>PLACEHOLDER: Halaman Transfer (Homomorphic Addition akan ada di sini)</h3>")