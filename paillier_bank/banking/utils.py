
import json
import os
import base64
from phe import paillier
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_aes_key_from_pin(pin, salt):
    """Mengubah PIN + Salt menjadi Kunci AES 32-byte"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(pin.encode()))

def decrypt_private_key(encrypted_blob_str, pin, salt_hex, pub_n):
    """
    Mendekripsi Private Key Paillier dari database menggunakan PIN user.
    """
    try:
        # 1. Regenerate Kunci AES dari PIN + Salt yang tersimpan
        salt = bytes.fromhex(salt_hex)
        key = generate_aes_key_from_pin(pin, salt)
        
        # 2. Dekripsi Blob JSON
        f = Fernet(key)
        # Fernet butuh bytes, db menyimpan string
        decrypted_json_bytes = f.decrypt(encrypted_blob_str.encode())
        
        # 3. Parsing JSON
        priv_data = json.loads(decrypted_json_bytes.decode())
        
        # 4. Rekonstruksi Objek Paillier
        # Kita perlu merekonstruksi Public Key dulu, baru Private Key
        public_key = paillier.PaillierPublicKey(n=int(pub_n))
        private_key = paillier.PaillierPrivateKey(
            public_key=public_key,
            p=int(priv_data['p']),
            q=int(priv_data['q'])
        )
        return private_key
    except Exception as e:
        # Jika PIN salah, Fernet akan raise InvalidToken / error dekripsi
        raise ValueError("Gagal mendekripsi private key. PIN mungkin salah.")