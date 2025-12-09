from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_rsa_keypair():
    """
    Menghasilkan Private Key dan Public Key.
    """
    # 1. Generate Private Key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # 2. Serialize Private Key (Untuk disimpan di DB)
    # Idealnya ini dienkripsi dengan password user/PIN, tapi untuk contoh ini kita buat plain PEM dulu
    # atau menggunakan BestEffort encryption.
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption() 
        # SANGAT DISARANKAN: Ganti NoEncryption() dengan 
        # serialization.BestAvailableEncryption(b'password_rahasia_user')
    )

    # 3. Generate Public Key
    public_key = private_key.public_key()
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pem_private.decode('utf-8'), pem_public.decode('utf-8')