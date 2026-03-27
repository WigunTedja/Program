import sys
import base64
import time

from banking.utils import generate_paillier_keypair

from django.test import SimpleTestCase

class TestRuangPaillier(SimpleTestCase):
    def get_real_int_byte_size(self, integer_val):
        """Menghitung ukuran byte murni dari sebuah integer."""
        if integer_val == 0:
            return 1
        return (integer_val.bit_length() + 7) // 8

    def test_ruang(self):
        # Variasi ukuran kunci (Catatan: 3072 bit di pure Python sangat lambat, bisa Anda tambahkan jika mau menunggu)
        key_sizes = [512, 1024, 2048, 3072]
        
        plaintexts = [10000,1000000,1000000000, 1000000000000]

        print("="*80)
        print("Evaluasi Ruang Skema Paillier")
        print("="*80)

        for k_size in key_sizes:
            print(f"\nMENGGENERATE KUNCI {k_size}-BIT")
            start_time = time.time()
            pub_key, priv_key = generate_paillier_keypair(n_length=k_size)
            print(f"Waktu generate kunci: {time.time() - start_time:.2f} detik")

            # Mengukur ukuran asli (Raw Bytes) dari Kunci
            pub_n_size = self.get_real_int_byte_size(pub_key.n)
            pub_g_size = self.get_real_int_byte_size(pub_key.g)
            priv_p_size = self.get_real_int_byte_size(priv_key.p)
            priv_q_size = self.get_real_int_byte_size(priv_key.q)

            print(f"--- UKURAN KUNCI REAL ---")
            print(f"Public Key (N + G) Raw Bytes : {pub_n_size + pub_g_size} bytes")
            print(f"Private Key (P + Q) Raw Bytes: {priv_p_size + priv_q_size} bytes")
            
            for pt in plaintexts:
                pt_byte_size = self.get_real_int_byte_size(pt)
                print(f"\n    [+] Skenario Plaintext: {pt}")
                print(f"        Ukuran Plaintext Raw  : {pt_byte_size} bytes")

                # MENGGUNAKAN PLAINTEXT SEBAGAI PARAMETER ENKRIPSI NYATA
                start_enc = time.time()
                encrypted_obj = pub_key.encrypt(pt)
                c_val = encrypted_obj.ciphertext()
                enc_time = time.time() - start_enc

                # Mengukur berbagai format Ciphertext
                # 1. Raw Byte (Paling ideal untuk database, menggunakan tipe data BYTEA/BLOB)
                c_blob = c_val.to_bytes(self.get_real_int_byte_size(c_val), 'big')
                c_blob_size = len(c_blob)

                # 2. Base64 (Ideal untuk transfer REST API / JSON)
                c_b64 = base64.b64encode(c_blob)
                c_b64_size = len(c_b64)

                # 3. String Desimal (Sistem yang Anda gunakan sekarang dengan models.TextField)
                c_str10 = str(c_val)
                c_str10_size = len(c_str10)

                # 4. String Hexadecimal
                c_hex = hex(c_val)[2:]
                c_hex_size = len(c_hex)

                print(f"        Waktu Enkripsi        : {enc_time:.4f} detik")
                print(f"        -- Ukuran Ciphertext Berdasarkan Format --")
                print(f"        Format BLOB/Bytes     : {c_blob_size} bytes")
                print(f"        Format Base64         : {c_b64_size} bytes")
                print(f"        Format Hexadecimal    : {c_hex_size} bytes")
                print(f"        Format String Desimal : {c_str10_size} bytes (YANG ANDA GUNAKAN SAAT INI)")

                print(f"        -- Rasio Ekspansi Data (Ukuran Ciphertext / Ukuran Plaintext) --")
                # Rasio ekspansi
                ratio_blob = c_blob_size / pt_byte_size
                ratio_str10 = c_str10_size / pt_byte_size
                print(f"        Rasio Jika Pakai BLOB : {ratio_blob:.2f}x lebih besar")
                print(f"        Rasio Jika Pakai Text : {ratio_str10:.2f}x lebih besar")
                
        print("\n" + "="*80)
        print(" KESIMPULAN ANALISIS")
        print("="*80)
        print("1. Ukuran Ciphertext Paillier SELALU KONSISTEN mengikuti ukuran kunci (N^2),")
        print("   tidak peduli seberapa kecil atau besar plaintext Anda.")
        print("2. Rasio ekspansi menjadi SANGAT BURUK ketika mengenkripsi data kecil (seperti ")
        print("   saldo 100.000) karena plaintext yang hanya beberapa byte membengkak menjadi")
        print("   ratusan byte (tergantung ukuran kunci).")
        print("3. Menyimpan angka raksasa menggunakan tipe data TEXT (String desimal) di ")
        print("   Django/PostgreSQL adalah cara yang boros, memakan ukuran ~2.4x lipat lebih ")
        print("   besar dari ukuran byte murninya.")
