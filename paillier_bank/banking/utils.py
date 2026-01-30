import json
import os
import base64
import random
import secrets
import math
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def get_prime(nbits):
    """
    Generates a prime number of nbits using the Miller-Rabin primality test.
    This is slow in pure Python but necessary for the assignment.
    """
    while True:
        p = secrets.randbits(nbits)
        if p % 2 == 0:
            p += 1
        if is_prime(p):
            return p

def is_prime(n, k=40):
    """Miller-Rabin primality test."""
    if n == 2 or n == 3: return True
    if n % 2 == 0 or n < 2: return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = secrets.randbelow(n - 4) + 2  # range [2, n-2]
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def lcm(a, b):
    return abs(a * b) // math.gcd(a, b)

def modinv(a, m):
    """Calculate modular inverse of a mod m."""
    return pow(a, -1, m)

class PublicKey:
    def __init__(self, n):
        self.n = int(n)
        self.n_sq = n * n
        self.g = n + 1 # Optimization: g = n + 1

    def encrypt(self, m):
        """
        Encrypts integer m.
        Formula: c = g^m * r^n mod n^2
        Optimized g=n+1: c = (1 + m*n) * r^n mod n^2
        """
        # Generate random r where gcd(r, n) = 1
        while True:
            r = secrets.randbelow(self.n - 1) + 1
            if math.gcd(r, self.n) == 1:
                break
        
        # Calculate parts
        gm = (1 + m * self.n) % self.n_sq
        rn = pow(r, self.n, self.n_sq)
        
        c = (gm * rn) % self.n_sq
        return EncryptedNumber(c, self)

class PrivateKey:
    def __init__(self, p, q, n, public_key):
        self.p = p
        self.q = q
        self.n = n
        self.public_key = public_key
        self.l = lcm(p - 1, q - 1)
        self.u = modinv(self.l, n)

    def decrypt(self, ciphertext_obj):
        """
        Mendekripsi ciphertext (int atau EncryptedNumber).
        Rumus: m = L(c^lambda mod n^2) * u mod n
        """
        # 1. Handle input flexibility (terima int murni atau objek EncryptedNumber)
        if isinstance(ciphertext_obj, EncryptedNumber):
            c = ciphertext_obj.ciphertext()
        elif isinstance(ciphertext_obj, int):
            c = ciphertext_obj
        else:
            raise TypeError("Ciphertext harus berupa integer atau EncryptedNumber")

        n = self.n
        n_sq = n * n
        
        try:
            # Di baris ini biasanya error terjadi jika c atau self.l adalah string
            c_lambda = pow(c, self.l, n_sq)
        except TypeError as e:
            print(f"CRITICAL ERROR: Gagal di pow(). Detail: {e}")
            raise e

        L_val = (c_lambda - 1) // n
        plaintext = (L_val * self.u) % n

        if plaintext > n // 2:
            plaintext = plaintext - n

        return plaintext

class EncryptedNumber:
    def __init__(self, ciphertext_val, public_key):
        self._ciphertext = ciphertext_val
        self.public_key = public_key

    def ciphertext(self):
        return self._ciphertext

# --- 3. Main Generator Function ---

def generate_paillier_keypair(n_length=1024):
    """
    Generates public and private keys.
    Note: n_length=1024 means p and q should be roughly 512 bits.
    """
    # Generating 512-bit primes takes time in Python!
    p = get_prime(n_length // 2)
    q = get_prime(n_length // 2)
    
    # Ensure p != q
    while p == q:
        q = get_prime(n_length // 2)
        
    n = p * q
    
    pub = PublicKey(n)
    priv = PrivateKey(p, q, n, pub)
    
    return pub, priv

def paillier_addition(c1, c2, n):
    """
    Menjumlahkan dua ciphertext.
    Dalam Paillier: D(c1 * c2 mod n^2) = m1 + m2
    """
    n_sq = n * n
    
    c_total = (c1 * c2) % n_sq
    return c_total

def paillier_subtraction(c1, c2, n):
    """
    Mengurangkan ciphertext c2 dari c1.
    Logika: D(c1 * inverse(c2) mod n^2) = m1 - m2
    """
    n_sq = n * n
    
    try:
        c2_inv = pow(c2, -1, n_sq)
    except ValueError:
        raise ValueError("Invers tidak ditemukan. Pastikan n dan c2 coprime (sangat jarang terjadi jika n valid).")

    c_diff = (c1 * c2_inv) % n_sq
    
    return c_diff

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
        public_key = PublicKey(n=int(pub_n))
        private_key = PrivateKey(
            p=int(priv_data['p']),
            q=int(priv_data['q']),
            n=int(priv_data['n']),
            public_key=public_key,
        )
        return private_key
    except Exception as e:
        # Jika PIN salah, Fernet akan raise InvalidToken / error dekripsi
        raise ValueError("Gagal mendekripsi private key. PIN mungkin salah.")

def encrypt_private_key(private_key_obj, pin):
    """Enkripsi Private Key Paillier menggunakan PIN"""
    # 1. Serialisasi Private Key ke JSON
    priv_data = {
        'p': private_key_obj.p,
        'q': private_key_obj.q,
        'n': private_key_obj.public_key.n
    }
    priv_json = json.dumps(priv_data)
    
    # 2. Generate Salt dan Kunci AES
    salt = os.urandom(16)
    key = generate_aes_key_from_pin(pin, salt)
    
    # 3. Enkripsi
    f = Fernet(key)
    encrypted_blob = f.encrypt(priv_json.encode())
    
    return salt.hex(), encrypted_blob.decode()

def paillier_encrypt(m, n, g):
    n_sq = n * n
    r = random.randint(1, n - 1)  # Random r
    # c = (g^m * r^n) mod n^2
    # Gunakan pow(base, exp, mod) untuk efisiensi big int
    gm = pow(g, m, n_sq)
    rn = pow(r, n, n_sq)
    c = (gm * rn) % n_sq
    return c