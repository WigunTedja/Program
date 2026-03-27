import sys
import base64
import random
import json
from django.test import SimpleTestCase
from banking import utils

class TestRuangPaillier(SimpleTestCase):
    def test_ruang(self):
        print("ANALISIS OVERHEAD PAILLIER ENCRYPTION (Key: 1024-bit)")

        # 1. Ukuran Plaintext (Contoh: Saldo Rp 100.000.000)
        plaintext = 100000000001111111111111111111111199999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999
        pt_bytes = plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big')
        pt_size_raw = len(pt_bytes)
        print(f"[PLAINTEXT]")
        print(f"Nilai          : {plaintext}")
        print(f"Ukuran Raw (Byte): {pt_size_raw} bytes")
        print("-" * 60)

        # 2. Ukuran Kunci (Public Key N & G, masing-masing 1024 bit)
        # Dalam implementasi riil, N adalah 1024 bit (128 bytes)
        PublicKey, PrivateKey = utils.generate_paillier_keypair(n_length=1024)
        
        PubKeySize = sys.getsizeof(PublicKey)
        PrivKeySize = sys.getsizeof(PrivateKey)
        
        print(f"[UKURAN KUNCI (Private KEY)]")
        print(f"Penyimpanan Raw/Blob : {PubKeySize} bytes")
        print("-" * 60)

        print(f"[UKURAN KUNCI (PUBLIC KEY)]")
        print(f"Penyimpanan Raw/Blob : {PrivKeySize} bytes")
        print("-" * 60)

        # 3. Ukuran Ciphertext (2048 bit karena modulo N^2)
        # Kita simulasikan angka acak 2048-bit sebagai ciphertext
        ciphertext = PublicKey.encrypt(plaintext).ciphertext()

        # A. Python Integer (Di dalam memori RAM server)
        ct_int_mem = sys.getsizeof(ciphertext)

        # B. Raw Bytes / BLOB (Ideal untuk Database PostgreSQL BYTEA)
        ct_blob = ciphertext.to_bytes(256, 'big')
        ct_blob_size = len(ct_blob)

        # C. Base64 (Ideal untuk transfer REST API JSON)
        ct_b64 = base64.b64encode(ct_blob)
        ct_b64_size = len(ct_b64)

        # D. String Hexadecimal
        ct_hex = hex(ciphertext)[2:]
        ct_hex_size = len(ct_hex)

        # E. String Desimal Basis 10 (YANG ANDA GUNAKAN SAAT INI DI TEXTFIELD)
        ct_str10 = str(ciphertext)
        ct_str10_size = len(ct_str10)

        print(f"[ANALISIS CIPHERTEXT (DATA PAYLOAD)]")
        print(f"Format Python Integer (Memori RAM) : {ct_int_mem} bytes")
        print(f"Format Blob/Bytes (Database BYTEA) : {ct_blob_size} bytes")
        print(f"Format Base64 (API Network)        : {ct_b64_size} bytes")
        print(f"Format String Hex                  : {ct_hex_size} bytes")
        print(f"Format String Desimal (Sistem Anda): {ct_str10_size} bytes")
        
        print("-" * 60)
        print(f"[RASIO EKSPANSI (Dibandingkan Plaintext {pt_size_raw} byte)]")
        print(f"Rasio Menggunakan Blob/Bytes : {ct_blob_size / pt_size_raw:.2f}x lebih besar")
        print(f"Rasio Menggunakan Base64     : {ct_b64_size / pt_size_raw:.2f}x lebih besar")
        print(f"Rasio Menggunakan Sistem Anda: {ct_str10_size / pt_size_raw:.2f}x lebih besar (!!!)")
        print("="*60)
