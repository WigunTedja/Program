from django.shortcuts import render, redirect
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from .models import Nasabah
from .utils import generate_rsa_keypair
from django.db import transaction
from .serializers import NasabahSerializer
from .models import Nasabah

# Mengimpor library Paillier Homomorphic Encryption
import phe

def index(request):
    return render(request, 'pages/index.html')

# ---------------------------------
# --- VIEW UNTUK AUTENTIKASI ---
# ---------------------------------


# TODO buat kunci aes, pin, dan paillier untuk akun nasabah  
# Registrasi akun nasabah
@transaction.atomic # Memastikan semua tersimpan atau tidak sama sekali
def registrasi_nasabah(request):
    if request.method == 'POST':
        # Mengambil data dari Form (Sesuai Diagram Step 4: Memberikan email, password, pin)
        nama_lengkap = request.POST.get('nama')
        email = request.POST.get('email')
        password = request.POST.get('password')
        pin = request.POST.get('pin')
        saldo_awal = request.POST.get('saldo_awal') # Di real case, ini diinput staff sebelumnya

        # 1. Validasi Data (Sesuai Diagram Step 5: Memverifikasi data)
        if User.objects.filter(email=email).exists():
            return render(request, 'register.html', {'error': 'Email sudah terdaftar'})

        # 2. Buat Akun User Django (Authentication)
        user = User.objects.create_user(
            username=email, # Kita pakai email sebagai username
            email=email,
            password=password
        )

        # 3. Generasi Keypair (Sesuai Diagram Step 6)
        private_key_pem, public_key_pem = generate_rsa_keypair()

        # 4. Simpan Data Nasabah
        nasabah = Nasabah.objects.create(
            user=user,
            nama_lengkap=nama_lengkap,
            saldo=saldo_awal,
            pin_hash=make_password(pin), # Hash PIN demi keamanan
            public_key=public_key_pem,
            encrypted_private_key=private_key_pem 
            # Catatan: Di produksi, enkripsi private key menggunakan PIN user di sini
        )

        # 5. Konfirmasi Berhasil (Sesuai Diagram Step 7)
        return render(request, 'success.html', {'nama': nama_lengkap})

    return render(request, 'register.html')

def login_nasabah(request):
    return render(request, status=200)


# class UserRegisterView(generics.CreateAPIView):
#     """
#     View untuk membuat user baru (Registrasi).
#     Endpoint: POST /api/auth/register/
#     """
#     queryset = User.objects.all()
#     serializer_class = UserRegisterSerializer
#     # Izinkan semua user (bahkan yang belum login) untuk mengakses endpoint ini.
#     permission_classes = [permissions.AllowAny]


# ---------------------------------
# --- VIEW UNTUK AKUN & TRANSAKSI ---
# ---------------------------------

# class DepositView(APIView):
#     """
#     View untuk menangani permintaan deposit ke akun user.
#     Memerlukan autentikasi JWT.
#     Endpoint: POST /api/account/deposit/
#     """
#     permission_classes = [permissions.IsAuthenticated]

#     def post(self, request, *args, **kwargs):
#         # 1. Ambil amount_ciphertext dari body request.
#         amount_ciphertext = request.data.get('amount_ciphertext')
#         if not amount_ciphertext:
#             return Response(
#                 {"error": "amount_ciphertext tidak boleh kosong."},
#                 status=status.HTTP_400_BAD_REQUEST
#             )

#         user = request.user
#         try:
#             # 2. Ambil objek Account dan PaillierKey milik user.
#             account = Account.objects.get(user=user)
#             paillier_key = PaillierKey.objects.get(user=user)
#         except (Account.DoesNotExist, PaillierKey.DoesNotExist):
#             return Response(
#                 {"error": "Akun atau kunci Paillier untuk user ini tidak ditemukan."},
#                 status=status.HTTP_404_NOT_FOUND
#             )

#         # --- OPERASI PENJUMLAHAN HOMOMORFIK ---
#         # PENTING: Proses konversi dari string ke objek phe dan sebaliknya.
        
#         try:
#             # A. Bangun ulang objek Kunci Publik dari string yang disimpan di database.
#             # Komponen n dan g harus diubah menjadi integer.
#             public_key = phe.PaillierPublicKey(n=int(paillier_key.public_key_n))

#             # B. Bangun ulang objek EncryptedNumber untuk saldo saat ini.
#             # Ciphertext dari database (string) diubah menjadi integer.
#             current_balance_encrypted = phe.EncryptedNumber(public_key, int(account.encrypted_balance))
            
#             # C. Bangun ulang objek EncryptedNumber untuk jumlah deposit.
#             deposit_amount_encrypted = phe.EncryptedNumber(public_key, int(amount_ciphertext))

#             # D. Lakukan penjumlahan homomorfik. Operasi terjadi pada data terenkripsi.
#             new_balance_encrypted = current_balance_encrypted + deposit_amount_encrypted

#             # E. Ubah hasil enkripsi kembali menjadi string untuk disimpan di database.
#             new_balance_ciphertext = str(new_balance_encrypted.ciphertext())
        
#         except Exception as e:
#             # Tangani jika ada error saat proses kriptografi
#             return Response(
#                 {"error": f"Terjadi kesalahan kriptografi: {str(e)}"},
#                 status=status.HTTP_500_INTERNAL_SERVER_ERROR
#             )

#         # ---------------------------------------------

#         # 4. Update field encrypted_balance dengan hasil penjumlahan.
#         account.encrypted_balance = new_balance_ciphertext
#         account.save()

#         # 5. Buat record baru di tabel Transaction.
#         transaction = Transaction.objects.create(
#             account=account,
#             transaction_type='DEPOSIT',
#             amount_ciphertext=amount_ciphertext
#         )

#         # Kirim response sukses dengan data transaksi yang baru dibuat.
#         serializer = TransactionSerializer(transaction)
#         return Response(serializer.data, status=status.HTTP_200_OK)