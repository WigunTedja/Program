def L_function(x, n):
    """Fungsi L(x) = (x - 1) // n"""
    return (x - 1) // n

def paillier_decrypt(ciphertext, n, g, lambd, mu):
    """
    Melakukan dekripsi Paillier.
    Args:
        ciphertext (int): Saldo terenkripsi.
        n (int): Kunci publik n.
        g (int): Kunci publik g (biasanya n+1).
        lambd (int): Kunci privat lambda.
        mu (int): Kunci privat mu.
    Returns:
        int: Plaintext (saldo asli).
    """
    n_sq = n * n
    
    # 1. Hitung c^lambda mod n^2
    u = pow(ciphertext, lambd, n_sq)
    
    # 2. Hitung L(u)
    l_u = L_function(u, n)
    
    # 3. Hitung (L(u) * mu) mod n
    plaintext = (l_u * mu) % n
    
    return plaintext