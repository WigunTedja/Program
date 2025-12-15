from django.db import models

# Create your models here.

from django.db import models
from django.contrib.auth.models import User
class Nasabah(models.Model):

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='nasabah')
    nama_lengkap = models.CharField(max_length=255)
    
    # Saldo saat ini (Ciphertext).
    # Disarankan: default value di-set saat user create, bukan di sini (karena butuh enkripsi '0')
    encrypted_saldo = models.TextField() 
    
    # Kunci Paillier
    pub_key_n = models.TextField()
    pub_key_g = models.TextField()
    
    # Private Key Terenkripsi (AES)
    priv_pail_key = models.TextField()
    
    # Keamanan
    pin_hash = models.CharField(max_length=128) # Untuk verifikasi login cepat tanpa dekripsi
    key_salt = models.CharField(max_length=64) # Diperbesar ke 64 (aman untuk 32-byte salt)
    
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.nama_lengkap} ({self.user.username})"
