import json
import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_rsa_keypair():
    """
    Menghasilkan Private Key dan Public Key.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption() 
        
    )

    public_key = private_key.public_key()
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pem_private.decode('utf-8'), pem_public.decode('utf-8')

def generate_aes_key_from_pin(pin, salt):
    """Mengubah PIN + Salt menjadi Kunci AES 32-byte"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(pin.encode()))

def encrypt_private_key(private_key_obj, pin):
    """Enkripsi Private Key Paillier menggunakan PIN"""
    
    priv_data = {
        'p': private_key_obj.p,
        'q': private_key_obj.q,
        'n': private_key_obj.public_key.n
    }
    priv_json = json.dumps(priv_data)
    
    salt = os.urandom(16)
    key = generate_aes_key_from_pin(pin, salt)
    
    f = Fernet(key)
    encrypted_blob = f.encrypt(priv_json.encode())
    
    return salt.hex(), encrypted_blob.decode()