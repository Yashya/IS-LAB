import random
import numpy as np
from sympy import mod_inverse

def generate_prime_candidate(length):
    """Generate a random prime number of specified bit length."""
    p = random.getrandbits(length)
    return p

def is_probable_prime(n, k=5):  # number of tests
    """Use Miller-Rabin primality test to check if n is prime."""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # Write n as d*2^r + 1
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Test for k iterations
    for _ in range(k):
        a = random.randint(2, n - 2)
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

def generate_prime_number(length):
    """Generate a prime number of a given bit length."""
    p = 4
    while not is_probable_prime(p):
        p = generate_prime_candidate(length)
    return p

def generate_paillier_keypair(bits=512):
    """Generate Paillier keypair (public and private keys)."""
    p = generate_prime_number(bits)
    q = generate_prime_number(bits)
    n = p * q
    nsquared = n * n
    g = n + 1  # g is typically chosen as n + 1
    lambda_val = (p - 1) * (q - 1)

    mu = mod_inverse(L(pow(g, lambda_val, nsquared), n), n)
    return (n, g), (lambda_val, mu)  # public key, private key

def L(x, n):
    """Helper function for Paillier."""
    return (x - 1) // n

def paillier_encrypt(public_key, plaintext):
    """Encrypt plaintext using the Paillier encryption scheme."""
    n, g = public_key
    r = random.randint(1, n - 1)
    c = (pow(g, plaintext, n * n) * pow(r, n, n * n)) % (n * n)
    return c

def paillier_decrypt(private_key, public_key, ciphertext):
    """Decrypt ciphertext using the Paillier decryption method."""
    n, _ = public_key
    lambda_val, mu = private_key
    u = pow(ciphertext, lambda_val, n * n)
    plaintext = L(u, n) * mu % n
    return plaintext

def main_paillier():
    # Generate Paillier keypair
    print("Generating Paillier keypair...")
    public_key, private_key = generate_paillier_keypair(bits=16)  # Using smaller bit size for demonstration

    # User input for two integers
    num1 = int(input("Enter the first integer to encrypt: "))
    num2 = int(input("Enter the second integer to encrypt: "))

    # Encrypt the integers
    encrypted_num1 = paillier_encrypt(public_key, num1)
    encrypted_num2 = paillier_encrypt(public_key, num2)

    print(f"Encrypted {num1}: {encrypted_num1}")
    print(f"Encrypted {num2}: {encrypted_num2}")

    # Simulate data sharing and secure calculation
    shared_encrypted_sum = (encrypted_num1 + encrypted_num2) % (public_key[0] ** 2)
    print(f"Encrypted sum (without decryption): {shared_encrypted_sum}")

    # Decrypt the result of the secure calculation
    decrypted_sum = paillier_decrypt(private_key, public_key, shared_encrypted_sum)
    print(f"Decrypted sum: {decrypted_sum}")
    print(f"Original sum: {num1 + num2}")

if __name__ == "__main__":
    main_paillier()
