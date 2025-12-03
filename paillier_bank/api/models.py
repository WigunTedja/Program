from django.db import models

# Create your models here.

from django.db import models
from django.contrib.auth.models import User

# Model untuk menyimpan kunci publik Paillier yang terasosiasi dengan setiap pengguna.
# Kunci ini penting untuk operasi kriptografi homomorfik pada saldo.
class PaillierKey(models.Model):
    # Relasi satu-ke-satu dengan model User bawaan Django.
    # Jika User dihapus, PaillierKey yang terkait juga akan terhapus (CASCADE).
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='paillier_key')
    
    # Komponen 'n' dari kunci publik, disimpan sebagai teks karena bisa sangat panjang.
    public_key_n = models.TextField()
    
    # Komponen 'g' dari kunci publik, juga disimpan sebagai teks.
    public_key_g = models.TextField()

    def __str__(self):
        return f"Kunci Paillier untuk {self.user.username}"

# Model untuk akun perbankan setiap pengguna.
class Account(models.Model):
    # Setiap pengguna hanya memiliki satu akun.
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='account')
    
    # Saldo disimpan dalam bentuk ciphertext (teks terenkripsi) untuk keamanan.
    # TextField digunakan untuk menampung string ciphertext yang mungkin panjang.
    encrypted_balance = models.TextField()

    def __str__(self):
        return f"Akun untuk {self.user.username}"

# Model untuk mencatat setiap transaksi yang terjadi.
class Transaction(models.Model):
    # Pilihan untuk tipe transaksi yang bisa terjadi.
    TRANSACTION_TYPES = [
        ('DEPOSIT', 'Deposit'),
        ('WITHDRAWAL', 'Withdrawal'),
        ('TRANSFER', 'Transfer'),
    ]

    # Relasi ForeignKey ke model Account. Satu akun bisa memiliki banyak transaksi.
    # Jika akun dihapus, semua riwayat transaksinya juga akan dihapus.
    account = models.ForeignKey(Account, on_delete=models.CASCADE, related_name='transactions')
    
    # Jenis transaksi, menggunakan pilihan yang sudah didefinisikan di atas.
    transaction_type = models.CharField(max_length=10, choices=TRANSACTION_TYPES)
    
    # Jumlah transaksi juga disimpan sebagai ciphertext.
    amount_ciphertext = models.TextField()
    
    # Waktu transaksi dicatat secara otomatis saat transaksi dibuat.
    timestamp = models.DateTimeField(auto_now_add=True)
    
    # ID akun lain yang terkait (misalnya, akun penerima dalam transfer).
    # Bisa kosong untuk DEPOSIT atau WITHDRAWAL.
    related_account_id = models.IntegerField(null=True, blank=True)

    def __str__(self):
        return f"{self.transaction_type} oleh {self.account.user.username} pada {self.timestamp.strftime('%Y-%m-%d %H:%M')}"