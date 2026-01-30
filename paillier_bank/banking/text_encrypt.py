import json
from .utils import EncryptedNumber

# Tentukan ukuran chunk agar m < n
# 1024 bit key ≈ 128 bytes. Kita ambil aman 64 char per chunk agar tidak overflow.
CHUNK_SIZE = 64 

def text_to_int(text):
    """Mengubah string menjadi integer besar."""
    return int.from_bytes(text.encode('utf-8'), 'big')

def int_to_text(number):
    """engubah integer besar kembali menjadi string."""
    # Hitung kebutuhan byte: (bit_length + 7) // 8
    length = (number.bit_length() + 7) // 8
    return number.to_bytes(length, 'big').decode('utf-8')

def encrypt_text(text, public_key):
    """
    Mengenakripsi teks panjang dengan memecahnya menjadi chunk,
    lalu mengenkripsi setiap chunk menggunakan public_key dari utils.
    
    Output: JSON String yang berisi list ciphertext (bisa disimpan di TextField DB).
    """
    if not text:
        return json.dumps([])

    encrypted_chunks = []
    
    # 1. Pecah teks menjadi potongan kecil (Chunking)
    # Ini wajib karena Paillier memiliki batas m < n
    for i in range(0, len(text), CHUNK_SIZE):
        chunk = text[i:i+CHUNK_SIZE]
        
        # 2. Ubah Chunk Teks ke Integer
        m = text_to_int(chunk)
        
        # 3. Enkripsi menggunakan method dari object public_key
        # Hasilnya adalah object EncryptedNumber (dari utils atau phe)
        enc_obj = public_key.encrypt(m)
        
        # 4. Ambil nilai ciphertext mentah (integer)
        # Kita perlu mengecek apakah objectnya dari utils sendiri atau library
        if hasattr(enc_obj, 'ciphertext'):
            # Jika itu method (seperti di phe asli) atau property
            c_val = enc_obj.ciphertext() 
        else:
            # Fallback jika return langsung int
            c_val = enc_obj
            
        encrypted_chunks.append(str(c_val))
    
    # Kembalikan sebagai string JSON agar mudah disimpan di database
    return json.dumps(encrypted_chunks)

def decrypt_text(encrypted_json, private_key, public_key):
    """
    Mendekripsi JSON String kembali menjadi teks asli.
    Memerlukan private_key untuk dekripsi dan public_key untuk rekonstruksi object.
    """
    if not encrypted_json:
        return ""

    try:
        # 1. Parse JSON
        cipher_list = json.loads(encrypted_json)
    except json.JSONDecodeError:
        return "" # Handle jika data bukan JSON valid

    decrypted_parts = []

    for c_str in cipher_list:
        c_val = int(c_str)
        
        # 2. Rekonstruksi EncryptedNumber (menggunakan class dari utils)
        # Beberapa library butuh object ini untuk didekripsi
        enc_obj = EncryptedNumber(c_val, public_key)
        
        # 3. Dekripsi (mendapatkan integer m)
        try:
            m = private_key.decrypt(enc_obj)
        except TypeError:
            # Fallback: jika private_key.decrypt menerima raw int
            m = private_key.decrypt(c_val)
            
        # 4. Ubah Integer kembali ke Teks
        part = int_to_text(m)
        decrypted_parts.append(part)

    # Gabungkan semua potongan
    return "".join(decrypted_parts)