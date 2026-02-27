from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import User
from django.contrib import messages
from django.db import transaction
from django.db.models import Q
from authentication.models import Nasabah
from django.http import HttpResponse
import hashlib
# from phe import paillier, EncryptedNumber
from .utils import EncryptedNumber, decrypt_private_key, encrypt_private_key, paillier_encrypt, generate_paillier_keypair, paillier_addition, paillier_subtraction, PublicKey, PrivateKey
from .models import Transaction
from . import text_encrypt


def is_admin(user):
    return user.is_authenticated and user.is_staff

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


@login_required(login_url='/auth/login/')
@user_passes_test(is_admin)
def admin_register_nasabah_page(request):
    if request.method == 'POST':
        nama_lengkap = request.POST.get('nama_lengkap')
        username = request.POST.get('username')
        alamat = request.POST.get('alamat')
        email = request.POST.get('email')
        nominal_setor = request.POST.get('nominal_setor')
        password = request.POST.get('password')
        pin = request.POST.get('pin')
        if User.objects.filter(username=username).exists():
            messages.error(request, "Username/Email sudah digunakan!")
            return render(request, 'pages/admin_register_nasabah.html')

        try:
            with transaction.atomic():
                user = User.objects.create_user(username=username, email=email, password=password)

                public_key, private_key = generate_paillier_keypair(n_length=1024)

                salt_hex, encrypted_priv_key = encrypt_private_key(private_key, pin)

                encrypted_saldo_obj = public_key.encrypt(nominal_setor)
                encrypted_saldo_str = str(encrypted_saldo_obj.ciphertext())

                pin_hash = hashlib.sha256(pin.encode()).hexdigest()

                encrypted_alamat = text_encrypt.encrypt_text(alamat, public_key)

                Nasabah.objects.create(
                    user=user,
                    nama_lengkap=nama_lengkap,
                    pub_key_n=str(public_key.n),
                    pub_key_g=str(public_key.g),
                    priv_pail_key=encrypted_priv_key,
                    key_salt=salt_hex,
                    pin_hash=pin_hash,
                    encrypted_saldo=encrypted_saldo_str,
                    alamat=encrypted_alamat
                )

                encrypted_deskripsi = text_encrypt.encrypt_text("Setoran Awal", public_key)
                Transaction.objects.create(
                    nasabah= nasabah,
                    transaction_type = 'SETOR',
                    amount_enc_sender= encrypted_saldo_str,
                    amount_enc_receiver= None,
                    related_nasabah= None,
                    deskripsi= encrypted_deskripsi,
                )

                messages.success(request, f"Sukses! Nasabah {nama_lengkap} berhasil didaftarkan dengan Kunci Homomorfik.")
                return redirect('admin-register-nasabah')

        except Exception as e:
            messages.error(request, f"Terjadi Kesalahan Sistem: {str(e)}")
            return render(request, 'pages/admin_register_nasabah.html')

    # Jika GET, tampilkan form kosong
    return render(request, 'pages/admin_register_nasabah.html')


@login_required(login_url='/auth/login/')
@user_passes_test(is_admin)
def admin_setor_tunai(request):
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        nominal_setor = request.POST.get('nominal_setor')
        deskripsi = request.POST.get('deskripsi')

        try:
            # Validasi input kosong
            if not nominal_setor or (not username and not email):
                raise ValueError("Data nasabah atau nominal tidak boleh kosong.")
            
            nominal_int = int(nominal_setor)
            if nominal_int <= 0:
                raise ValueError("Nominal setor harus positif.")

            with transaction.atomic():
                filters = Q()

                if username:
                    filters |= Q(username=username)
                if email:
                    filters |= Q(email=email)

                if not filters:
                    raise ValueError("Isikan username atau email nasabah")
                
                user_query = User.objects.filter(filters)
                
                if not user_query.exists():
                    raise ValueError("User dengan username/email tersebut tidak ditemukan.")

                target_user = user_query.get()

                # select_for_update() akan menahan transaksi lain sampai ini selesai
                nasabah = Nasabah.objects.select_for_update().get(user=target_user)

                n = int(nasabah.pub_key_n)
                public_key = PublicKey(n)
                
                plain_setor = int(nominal_setor)
                cipher_setor = public_key.encrypt(plain_setor)
                cipher_saldo = int(nasabah.encrypted_saldo)

                cipher_saldo_baru = paillier_addition(cipher_saldo, cipher_setor.ciphertext(), n)

                nasabah.encrypted_saldo = str(cipher_saldo_baru)
                nasabah.save()

                encrypted_deskripsi = text_encrypt.encrypt_text(deskripsi, public_key)
                Transaction.objects.create(
                    nasabah= nasabah,
                    transaction_type = 'SETOR',
                    amount_enc_sender= str(cipher_setor.ciphertext()),
                    amount_enc_receiver= None,
                    related_nasabah= None,
                    deskripsi= encrypted_deskripsi,
                )

                messages.success(request, f"Sukses! Saldo  ditambahkan ke {nasabah.nama_lengkap}.")
                return redirect('admin-setor-tunai') 

        except Nasabah.DoesNotExist:
            messages.error(request, "User ditemukan, tapi belum terdaftar sebagai Nasabah (Profile belum dibuat).")
        except ValueError as ve:
            messages.error(request, str(ve))
        except Exception as e:
            messages.error(request, f"Terjadi Kesalahan Sistem: {str(e)}")
            
    return render(request, 'pages/admin_setor_tunai.html')

def admin_tarik_tunai(request):
    if request.method == 'POST':
        username = request.POST.get('username','').strip()
        email = request.POST.get('email','').strip()
        nominal_tarik = request.POST.get('nominal_tarik')
        deskripsi = request.POST.get('deskripsi')

        try:
            # Validasi input kosong
            if not nominal_tarik or (not username and not email):
                raise ValueError("Data nasabah atau nominal tidak boleh kosong.")
            
            nominal_int = int(nominal_tarik)
            if nominal_int <= 0:
                raise ValueError("Nominal tarik harus positif.")

            with transaction.atomic():
                filters =Q()

                if username:
                    filters |= Q(username=username)
                if email:
                    filters |= Q(email=email)
                if not filters:
                    raise ValueError("Isikan username atau email nasabah")
                
                user_query = User.objects.filter(filters)
                
                if not user_query.exists():
                    raise ValueError("User dengan username/email tersebut tidak ditemukan.")

                target_user = user_query.get()

                nasabah = Nasabah.objects.select_for_update().get(user=target_user)

                n = int(nasabah.pub_key_n)
                public_key = PublicKey(n)
                
                plain_tarik = int(nominal_tarik)
                cipher_tarik = public_key.encrypt(plain_tarik)
                cipher_saldo = int(nasabah.encrypted_saldo)

                cipher_saldo_baru = paillier_subtraction(cipher_saldo, cipher_tarik.ciphertext(), n)
                
                nasabah.encrypted_saldo = str(cipher_saldo_baru)
                nasabah.save()

                encrypted_deskripsi = text_encrypt.encrypt_text(deskripsi, public_key)

                Transaction.objects.create(
                    nasabah=nasabah,
                    transaction_type = 'TARIK',
                    amount_enc_sender = str(cipher_tarik.ciphertext()),
                    amount_enc_receiver = None,
                    related_nasabah = None,
                    deskripsi = encrypted_deskripsi,
                )

                messages.success(request, f"Sukses! Saldo  ditarik dari {nasabah.nama_lengkap}.")
                return redirect('admin-tarik-tunai') 

        except Nasabah.DoesNotExist:
            messages.error(request, "User ditemukan, tapi belum terdaftar sebagai Nasabah (Profile belum dibuat).")
        except ValueError as ve:
            messages.error(request, str(ve))
        except Exception as e:
            messages.error(request, f"Terjadi Kesalahan Sistem: {str(e)}")

    return render(request, 'pages/admin_tarik_tunai.html')


@login_required(login_url='login')
def lihat_saldo(request):
    nasabah = request.user.nasabah 
    saldo_plain = None
    error_msg = None

    if request.method == 'POST':
        pin_input = request.POST.get('pin')

        # Verifikasi Hash PIN
        input_hash = hashlib.sha256(pin_input.encode()).hexdigest()
        
        if input_hash != nasabah.pin_hash:
            messages.error(request, "PIN Salah!")
        else:
            try:
                private_key = decrypt_private_key(
                    encrypted_blob_str=nasabah.priv_pail_key,
                    pin=pin_input,
                    salt_hex=nasabah.key_salt,
                    pub_n=nasabah.pub_key_n
                )

                encrypted_saldo_int = int(nasabah.encrypted_saldo)
                
                publicKey_nasabah = PublicKey(int(nasabah.pub_key_n))
                
                saldo_plain = private_key.decrypt(encrypted_saldo_int)
                
                messages.success(request, "Saldo berhasil didekripsi.")
                
            except Exception as e:
                error_msg = f"Error Dekripsi: {str(e)}"
                print(f"DEBUG: Error={str(e)}")
                messages.error(request, error_msg)

    return render(request, 'pages/lihat_saldo.html', {
        'nasabah': nasabah,
        'saldo': saldo_plain
    })

@login_required(login_url='login')
def riwayat_transaksi(request):
    nasabah = request.user.nasabah
    transactions_decrypted = []
    pin_verified = False

    error_msg = None
    if request.method == 'POST':
        pin_input = request.POST.get('pin')

        # Verifikasi Hash PIN
        input_hash = hashlib.sha256(pin_input.encode()).hexdigest()
        
        if input_hash != nasabah.pin_hash:
            messages.error(request, "PIN Salah!")
        else:
            try:
                transaksi_list = Transaction.objects.filter(nasabah=nasabah).order_by('-timestamp')
                private_key = decrypt_private_key(
                    encrypted_blob_str=nasabah.priv_pail_key,
                    pin=pin_input,
                    salt_hex=nasabah.key_salt,
                    pub_n=nasabah.pub_key_n
                )
                
                public_key = PublicKey(int(nasabah.pub_key_n))
                
                for tx in transaksi_list:
                    deskripsi = "Gagal mendekripsi deskripsi."
                    nominal = "Gagal mendekripsi nominal"
                    if tx.deskripsi:
                        deskripsi = text_encrypt.decrypt_text(tx.deskripsi,private_key,public_key)                    
                    if tx.amount_enc_sender:
                        nominal = private_key.decrypt(int(tx.amount_enc_sender))

                    transactions_decrypted.append({
                        'timestamp': tx.timestamp,
                        'type': tx.transaction_type,
                        'deskripsi': deskripsi,
                        'amount_enc': nominal
                    })
                
                pin_verified = True
                messages.success(request, "Riwayat transaksi berhasil didekripsi.")

            except Exception as e:
                error_msg = f"Error Dekripsi: {str(e)}"
                print(f"DEBUG: Error={str(e)}")
                messages.error(request, error_msg)

    context = {
        'transaksi': transactions_decrypted if pin_verified else None,
        'pin_verified': pin_verified
    }
    return render(request, 'pages/riwayat_transaksi.html', context)

def profil_nasabah(request):
    nasabah = request.user.nasabah
    alamat_plain = None
    pin_verified = False

    if request.method == 'POST':
        pin_input = request.POST.get('pin')
        input_hash = hashlib.sha256(pin_input.encode()).hexdigest()

        if input_hash != nasabah.pin_hash:
            messages.error(request, "PIN Salah!")
        else:
            try:
                private_key = decrypt_private_key(
                    encrypted_blob_str=nasabah.priv_pail_key,
                    pin=pin_input,
                    salt_hex=nasabah.key_salt,
                    pub_n=nasabah.pub_key_n,
                )
                public_key = PublicKey(int(nasabah.pub_key_n))

                if nasabah.alamat:
                    alamat_plain = text_encrypt.decrypt_text(nasabah.alamat, private_key, public_key)
                else:
                    alamat_plain = "Alamat tidak ditemukan."
                
                pin_verified = True
                messages.success(request, "Profil berhasil didekripsi.")
            except Exception as e:
                messages.error(request, f"Gagal mendekripsi profil nasabah.")

    context ={
        'nasabah':nasabah,
        'alamat':alamat_plain,
        'pin_verified': pin_verified,
    }
    return render(request, 'pages/profil nasabah.html', context)