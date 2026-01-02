from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import User
from django.contrib import messages
from django.db import transaction
from django.db.models import Q
from authentication.models import Nasabah
from django.http import HttpResponse
import hashlib
from phe import paillier, EncryptedNumber
from .utils import decrypt_private_key, encrypt_private_key, paillier_encrypt


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
        email = request.POST.get('email')
        password = request.POST.get('password')
        pin = request.POST.get('pin')
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


@login_required(login_url='/auth/login/')
@user_passes_test(is_admin)
def admin_setor_tunai(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        nominal_setor = request.POST.get('nominal_setor')

        try:
            # Validasi input kosong
            if not nominal_setor or (not username and not email):
                raise ValueError("Data nasabah atau nominal tidak boleh kosong.")
            
            nominal_int = int(nominal_setor)
            if nominal_int <= 0:
                raise ValueError("Nominal setor harus positif.")

            with transaction.atomic():
                # 1. Cari User (Username OR Email)
                # Gunakan Q objects untuk logika OR
                user_query = User.objects.filter(Q(username=username) | Q(email=email))
                
                if not user_query.exists():
                    raise ValueError("User dengan username/email tersebut tidak ditemukan.")

                target_user = user_query.first()

                # 2. Get Nasabah dengan Lock (Mencegah Race Condition)
                # select_for_update() akan menahan transaksi lain sampai ini selesai
                nasabah = Nasabah.objects.select_for_update().get(user=target_user)

                # 3. Ambil Public Key & Konversi ke Integer
                # Asumsi di model disimpan sebagai string/text
                # n = int(nasabah.pub_key_n)
                # g = int(nasabah.pub_key_g)
                # n_sq = n * n

                pub_key = paillier.PaillierPublicKey(n=int(nasabah.pub_key_n))

                # 4. Encrypt Nominal Setor (m_deposit -> c_deposit)
                # c_deposit = paillier_encrypt(nominal_int, n, g)
                c_saldo = EncryptedNumber(pub_key, int(nasabah.encrypted_saldo))
                c_setor = pub_key.encrypt(int(nominal_setor))
                # 5. Operasi Homomorphic Addition
                # Rumus: c_new = (c_current * c_deposit) mod n^2
                # c_current = int(nasabah.saldo_encrypted)
                
                # c_total = (c_current * c_deposit) % n_sq
                c_total_saldo = c_saldo + c_setor


                # 6. Simpan Hasil (Kembalikan ke string)
                nasabah.encrypted_saldo = str(c_total_saldo.ciphertext())
                nasabah.save()

                messages.success(request, f"Sukses! Saldo  ditambahkan ke {nasabah.nama_lengkap}.")
                return redirect('admin-setor-tunai') 

        except Nasabah.DoesNotExist:
            messages.error(request, "User ditemukan, tapi belum terdaftar sebagai Nasabah (Profile belum dibuat).")
        except ValueError as ve:
            messages.error(request, str(ve))
        except Exception as e:
            messages.error(request, f"Terjadi Kesalahan Sistem: {str(e)}")
            
    return render(request, 'pages/admin_setor_tunai.html')


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