from django.db import models

# Model untuk mencatat setiap transaksi yang terjadi.
class Transaction(models.Model):
    # Pilihan untuk tipe transaksi yang bisa terjadi.
    TRANSACTION_TYPES = [
        ('SETOR', 'Setor Tunai'),
        ('TARIK', 'Tarik Tunai'),
        ('TRANSFER', 'Transfer'),
    ]
    # Dengan menggunakan string ('authentication.nasanah') 
    # maka django akan otomatis mencari model tersebut secara lazy loading
    nasabah = models.ForeignKey('authentication.Nasabah', on_delete=models.CASCADE, related_name='transactions')
    transaction_type = models.CharField(max_length=10, choices=TRANSACTION_TYPES)

    # 1. Nominal untuk Pengirim/Nasabah utama (Dienkripsi dgn Public Key Nasabah)
    # Digunakan untuk mengurangi saldo Nasabah saat Transfer/Withdraw
    # Atau menambah saldo saat Deposit.
    amount_enc_sender = models.TextField(help_text="Nominal encrypted with Nasabah PK")
    
    # 2. Nominal untuk Penerima (Dienkripsi dgn Public Key Penerima)
    # HANYA TERISI JIKA TIPE TRANSAKSI = TRANSFER
    amount_enc_receiver = models.TextField(null=True, blank=True, help_text="Nominal encrypted with Receiver PK")

    # Akan dienkripsi
    deskripsi = models.TextField(null=True, blank=True)
    
    # Menggunakan ForeignKey agar data konsisten. Jika penerima dihapus, set null.
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