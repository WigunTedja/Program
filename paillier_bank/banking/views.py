# views.py
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse

@login_required(login_url='login') # Pastikan mengarah ke nama URL login Anda
def dashboard(request):
    """
    Halaman utama setelah nasabah login.
    Menampilkan menu navigasi utama.
    """
    context = {
        'user': request.user, # Mengirim data user ke template
    }
    return render(request, 'dashboard.html', context)

# --- PLACEHOLDERS ---

@login_required(login_url='login')
def lihat_saldo(request):
    # TODO: Nanti di sini kita ambil ciphertext saldo -> dekripsi paillier -> tampilkan
    return HttpResponse("<h3>PLACEHOLDER: Halaman Lihat Saldo (Dekripsi Paillier akan ada di sini)</h3>")

@login_required(login_url='login')
def transfer_saldo(request):
    # TODO: Nanti di sini form transfer -> homomorphic addition -> update DB
    return HttpResponse("<h3>PLACEHOLDER: Halaman Transfer (Homomorphic Addition akan ada di sini)</h3>")