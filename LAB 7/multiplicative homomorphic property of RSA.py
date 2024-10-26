import random
import math
from sympy import randprime


# Helper function for modular exponentiation
def mod_exp(base, exp, mod):
    result = 1
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp //= 2
    return result


# RSA Key Generation
def generate_rsa_keys(bit_length=512):
    # Generate two large random prime numbers p and q
    p = randprime(2 ** (bit_length // 2 - 1), 2 ** (bit_length // 2))
    q = randprime(2 ** (bit_length // 2 - 1), 2 ** (bit_length // 2))

    n = p * q
    phi_n = (p - 1) * (q - 1)

    # Choose e such that 1 < e < phi_n and gcd(e, phi_n) = 1
    e = 65537  # Common choice for e
    while math.gcd(e, phi_n) != 1:
        e = random.randint(2, phi_n - 1)

    # Calculate d as the modular inverse of e mod phi_n
    d = pow(e, -1, phi_n)

    # Public key (n, e) and Private key (n, d)
    return (n, e), (n, d)


# RSA Encryption
def rsa_encrypt(public_key, plaintext):
    n, e = public_key
    return mod_exp(plaintext, e, n)


# RSA Decryption
def rsa_decrypt(private_key, ciphertext):
    n, d = private_key
    return mod_exp(ciphertext, d, n)


# Testing the multiplicative homomorphic property
# Generate RSA keys
public_key, private_key = generate_rsa_keys()

# Encrypt two integers
plaintext1 = 7
plaintext2 = 3
ciphertext1 = rsa_encrypt(public_key, plaintext1)
ciphertext2 = rsa_encrypt(public_key, plaintext2)
print("Ciphertext 1:", ciphertext1)
print("Ciphertext 2:", ciphertext2)

# Multiplicative homomorphic operation (multiplying ciphertexts)
ciphertext_product = (ciphertext1 * ciphertext2) % public_key[0]
print("Ciphertext of product (homomorphic multiplication):", ciphertext_product)

# Decrypt the result
decrypted_product = rsa_decrypt(private_key, ciphertext_product)
print("Decrypted product:", decrypted_product)

# Verify
expected_product = plaintext1 * plaintext2
print("Expected product:", expected_product)
assert decrypted_product == expected_product, "The decrypted product does not match the expected value!"
