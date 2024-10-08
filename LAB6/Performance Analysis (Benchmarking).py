import random
import time
from sympy import mod_inverse


# Paillier Encryption Scheme
def generate_prime_candidate(length):
    """Generate a random prime number of specified bit length."""
    p = random.getrandbits(length)
    return p


def is_prime(n, k=5):  # number of tests
    """Use Miller-Rabin primality test to check if n is prime."""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(length):
    """Generate a prime number of a given bit length."""
    p = 4
    while not is_prime(p):
        p = generate_prime_candidate(length)
    return p


def paillier_keygen(bits=512):
    """Generate Paillier key pair."""
    p = generate_prime(bits)
    q = generate_prime(bits)
    n = p * q
    nsquared = n * n
    g = n + 1
    lambda_val = (p - 1) * (q - 1)

    # Calculate mu
    mu = mod_inverse((pow(g, lambda_val, nsquared) - 1) // n, n)

    # Return public key (n, n^2, g) and private key (mu, lambda)
    return (n, nsquared, g), (mu, lambda_val)


def paillier_encrypt(public_key, plaintext):
    """Encrypt plaintext using the Paillier encryption scheme."""
    n, nsquared, g = public_key
    r = random.randint(1, n - 1)  # Randomly chosen integer
    ciphertext = (pow(g, plaintext, nsquared) * pow(r, n, nsquared)) % nsquared
    return ciphertext


def paillier_decrypt(private_key, public_key, ciphertext):
    """Decrypt ciphertext using the Paillier decryption method."""
    n, nsquared, g = public_key
    mu, lambda_val = private_key

    # Calculate plaintext
    u = pow(ciphertext, lambda_val, nsquared)
    plaintext = (u - 1) // n * mu % n
    return plaintext


# ElGamal Encryption Scheme
def elgamal_keygen(bits=512):
    """Generate ElGamal key pair."""
    p = generate_prime(bits)
    g = random.randint(2, p - 1)  # Generator
    x = random.randint(1, p - 2)  # Private key
    y = pow(g, x, p)  # Public key

    return (p, g, y), x  # public_key, private_key


def elgamal_encrypt(public_key, plaintext):
    """Encrypt plaintext using the ElGamal encryption scheme."""
    p, g, y = public_key
    k = random.randint(1, p - 2)  # Randomly chosen integer
    c1 = pow(g, k, p)  # First part of ciphertext
    c2 = (plaintext * pow(y, k, p)) % p  # Second part of ciphertext
    return (c1, c2)


def elgamal_decrypt(private_key, public_key, ciphertext):
    """Decrypt ciphertext using the ElGamal decryption method."""
    p, _, _ = public_key
    c1, c2 = ciphertext
    s = pow(c1, private_key, p)
    plaintext = (c2 * mod_inverse(s, p)) % p
    return plaintext


# Performance Benchmarking
def benchmark_paillier():
    start_time = time.time()
    public_key, private_key = paillier_keygen(bits=16)
    keygen_time = time.time() - start_time

    plaintext = random.randint(1, 100)
    start_time = time.time()
    ciphertext = paillier_encrypt(public_key, plaintext)
    encrypt_time = time.time() - start_time

    start_time = time.time()
    decrypted_text = paillier_decrypt(private_key, public_key, ciphertext)
    decrypt_time = time.time() - start_time

    return keygen_time, encrypt_time, decrypt_time, plaintext, decrypted_text


def benchmark_elgamal():
    start_time = time.time()
    public_key, private_key = elgamal_keygen(bits=16)
    keygen_time = time.time() - start_time

    plaintext = random.randint(1, 100)
    start_time = time.time()
    ciphertext = elgamal_encrypt(public_key, plaintext)
    encrypt_time = time.time() - start_time

    start_time = time.time()
    decrypted_text = elgamal_decrypt(private_key, public_key, ciphertext)
    decrypt_time = time.time() - start_time

    return keygen_time, encrypt_time, decrypt_time, plaintext, decrypted_text


def main():
    print("Benchmarking Paillier:")
    paillier_results = benchmark_paillier()
    print(f"Key Generation Time: {paillier_results[0]:.6f} seconds")
    print(f"Encryption Time: {paillier_results[1]:.6f} seconds")
    print(f"Decryption Time: {paillier_results[2]:.6f} seconds")
    print(f"Original plaintext: {paillier_results[3]}, Decrypted: {paillier_results[4]}")

    print("\nBenchmarking ElGamal:")
    elgamal_results = benchmark_elgamal()
    print(f"Key Generation Time: {elgamal_results[0]:.6f} seconds")
    print(f"Encryption Time: {elgamal_results[1]:.6f} seconds")
    print(f"Decryption Time: {elgamal_results[2]:.6f} seconds")
    print(f"Original plaintext: {elgamal_results[3]}, Decrypted: {elgamal_results[4]}")


if __name__ == "__main__":
    main()
