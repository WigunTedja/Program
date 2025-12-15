from rest_framework import serializers
from .models import Nasabah
# from ..banking.models import Transaction

class NasabahSerializer(serializers.ModelSerializer):
    class Meta:
        model = Nasabah
        fields = [
            'id', 
            'user', 
            'nama_lengkap', 
            'pub_key_n', 
            'pub_key_g', 
            'encrypted_saldo',
            'created_at'
        ]
        # Field ini hanya bisa DIBACA oleh frontend, tidak bisa DIEDIT/DIINPUT
        read_only_fields = ['id', 'created_at', 'encrypted_saldo', 'user']

    # Catatan: Kita exclude 'priv_pail_key', 'pin_hash', dan 'key_salt' 
    # agar data rahasia ini TIDAK TERKIRIM ke frontend saat get list nasabah.

# class TransactionSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Transaction
#         fields = [
#             'id',
#             'nasabah',
#             'transaction_type',
#             'amount_enc_sender',
#             'amount_enc_receiver',
#             'related_nasabah',
#             'timestamp'
#         ]
#         # ID dan Timestamp otomatis dibuat sistem, user tidak boleh isi.
#         read_only_fields = ['id', 'timestamp']