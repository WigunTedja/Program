import json
from .utils import EncryptedNumber

CHUNK_SIZE = 64 

def text_to_int(text):
    """Mengubah string menjadi integer besar."""
    return int.from_bytes(text.encode('utf-8'), 'big')

def int_to_text(number):
    """engubah integer besar kembali menjadi string."""
    
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
    
    for i in range(0, len(text), CHUNK_SIZE):
        chunk = text[i:i+CHUNK_SIZE]
        
        m = text_to_int(chunk)
        
        enc_obj = public_key.encrypt(m)
        
        if hasattr(enc_obj, 'ciphertext'):
            c_val = enc_obj.ciphertext() 
        else:
            c_val = enc_obj
            
        encrypted_chunks.append(str(c_val))
    
    return json.dumps(encrypted_chunks)

def decrypt_text(encrypted_json, private_key, public_key):
    """
    Mendekripsi JSON String kembali menjadi teks asli.
    Memerlukan private_key untuk dekripsi dan public_key untuk rekonstruksi object.
    """
    if not encrypted_json:
        return ""

    try:
        cipher_list = json.loads(encrypted_json)
    except json.JSONDecodeError:
        return "" 

    decrypted_parts = []

    for c_str in cipher_list:
        c_val = int(c_str)
        
        enc_obj = EncryptedNumber(c_val, public_key)
        
        try:
            m = private_key.decrypt(enc_obj)
        except TypeError:
            m = private_key.decrypt(c_val)
            
        part = int_to_text(m)
        decrypted_parts.append(part)

    return "".join(decrypted_parts)