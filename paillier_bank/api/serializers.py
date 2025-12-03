from rest_framework import serializers
from django.contrib.auth.models import User
from .models import PaillierKey, Transaction, Account

# 1. Serializer untuk Registrasi User Baru
class UserRegisterSerializer(serializers.ModelSerializer):
    """
    Serializer untuk membuat objek User baru.
    Hanya menerima username dan password.
    """
    class Meta:
        model = User
        fields = ['id', 'username', 'password']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        """
        Override method create untuk melakukan hashing pada password
        menggunakan metode create_user dari model manager User.
        """
        user = User.objects.create_user(
            username=validated_data['username'],
            password=validated_data['password']
        )
        return user

# 2. Serializer untuk Kunci Publik Paillier
class PaillierKeySerializer(serializers.ModelSerializer):
    """
    Serializer untuk membuat atau menampilkan Paillier Public Key.
    """
    class Meta:
        model = PaillierKey
        # 'user' dikecualikan karena akan diisi secara otomatis
        # berdasarkan user yang sedang login di dalam view.
        fields = ['public_key_n', 'public_key_g']


# 3. Serializer untuk Menampilkan Riwayat Transaksi
class TransactionSerializer(serializers.ModelSerializer):
    """
    Serializer untuk menampilkan daftar transaksi (read-only).
    """
    # Menambahkan field username pemilik akun agar lebih informatif
    username = serializers.ReadOnlyField(source='account.user.username')

    class Meta:
        model = Transaction
        fields = [
            'id',
            'username',
            'transaction_type',
            'amount_ciphertext',
            'timestamp',
            'related_account_id'
        ]

# 4. Serializer Sederhana untuk Input Transaksi (Transfer)
class TransferSerializer(serializers.Serializer):
    """
    Serializer ini bukan ModelSerializer. Tujuannya hanya untuk memvalidasi
    input dari user saat akan melakukan transaksi transfer.
    """
    amount_ciphertext = serializers.CharField()
    recipient_username = serializers.CharField(max_length=150)

    def validate_recipient_username(self, value):
        """
        Validasi kustom untuk memastikan user penerima ada di database.
        """
        if not User.objects.filter(username=value).exists():
            raise serializers.ValidationError("Pengguna penerima tidak ditemukan.")
        return value