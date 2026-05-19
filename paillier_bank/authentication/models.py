from django.db import models
from django.contrib.auth.models import User
class Nasabah(models.Model):

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='nasabah')
    nama_lengkap = models.CharField(max_length=255)

    alamat = models.TextField(null=True, blank=True)
    encrypted_saldo = models.TextField() 
    
    pub_key_n = models.TextField()
    pub_key_g = models.TextField()
    
    priv_pail_key = models.TextField()
    
    pin_hash = models.CharField(max_length=128) 
    key_salt = models.CharField(max_length=64) 
    
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.nama_lengkap} ({self.user.username})"
