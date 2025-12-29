# views.py
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from authentication.models import Nasabah
from django.http import HttpResponse
import hashlib
from phe import paillier
from .utils import decrypt_private_key


@login_required(login_url='login') # Pastikan mengarah ke nama URL login Anda
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