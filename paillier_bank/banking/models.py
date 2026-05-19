from django.db import models

class Transaction(models.Model):
    TRANSACTION_TYPES = [
        ('SETOR', 'Setor Tunai'),
        ('TARIK', 'Tarik Tunai'),
        ('TRANSFER', 'Transfer'),
    ]
    nasabah = models.ForeignKey('authentication.Nasabah', on_delete=models.CASCADE, related_name='transactions')
    transaction_type = models.CharField(max_length=10, choices=TRANSACTION_TYPES)

    amount_enc_sender = models.TextField(help_text="Nominal encrypted with Nasabah PK")
    
    amount_enc_receiver = models.TextField(null=True, blank=True, help_text="Nominal encrypted with Receiver PK")

    deskripsi = models.TextField(null=True, blank=True)
    
    related_nasabah = models.ForeignKey(
        'authentication.Nasabah', 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='related_transactions',
        verbose_name="Penerima / Pengirim Terkait"
    )

    timestamp = models.DateTimeField(auto_now_add=True)
    def __str__(self):
        return f"{self.transaction_type} oleh {self.nasabah.nama_lengkap} pada {self.timestamp.strftime('%Y-%m-%d %H:%M')}"