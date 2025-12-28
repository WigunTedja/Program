# views.py
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse

from .utils import paillier_decrypt

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

# --- PLACEHOLDERS ---

@login_required(login_url='login')
def lihat_saldo(request):
    try:
        # Mengambil profil nasabah dari user yang sedang login
        nasabah = request.user.nasabah
    except AttributeError:
        return HttpResponse("Error: User ini tidak memiliki profil Nasabah.")

    # --- PENGAMBILAN DATA ---
    # Pastikan data diambil sebagai integer karena di database biasanya disimpan sebagai String/Char
    # karena angkanya sangat besar.
    c_saldo = int(nasabah.encrypted_saldo)
    
    # Kunci Publik
    n = int(nasabah.pub_key_n)
    g = int(nasabah.pub_key_g) 
    
    # Kunci Privat (Hati-hati: Dalam produksi nyata, kunci privat tidak boleh
    # sembarangan diakses server seperti ini, tapi untuk simulasi ini oke)
    lambd = int(nasabah.private_lambda)
    mu = int(nasabah.private_mu)

    # --- PROSES DEKRIPSI PAILLIER ---
    saldo_asli = paillier_decrypt(c_saldo, n, g, lambd, mu)

    # --- TAMPILKAN ---
    context = {
        'nama': request.user.username,
        'saldo': saldo_asli,
        # Opsional: Tampilkan ciphertext juga untuk demo edukasi
        'encrypted_saldo_preview': str(c_saldo)[:50] + "..." 
    }
    
    return render(request, 'bank/lihat_saldo.html', context)

@login_required(login_url='login')
def transfer_saldo(request):
    # TODO: Nanti di sini form transfer -> homomorphic addition -> update DB
    return HttpResponse("<h3>PLACEHOLDER: Halaman Transfer (Homomorphic Addition akan ada di sini)</h3>")