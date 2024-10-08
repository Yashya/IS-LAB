import random
from sympy import mod_inverse

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

def elgamal_multiply(c1_a, c2_a, c1_b, c2_b, p):
    """Homomorphic multiplication of two ciphertexts."""
    c1 = (c1_a * c1_b) % p
    c2 = (c2_a * c2_b) % p
    return (c1, c2)

def elgamal_decrypt(private_key, public_key, ciphertext):
    """Decrypt ciphertext using the ElGamal decryption method."""
    p, _, _ = public_key
    c1, c2 = ciphertext
    s = pow(c1, private_key, p)
    plaintext = (c2 * mod_inverse(s, p)) % p
    return plaintext

def main_elgamal():
    # Generate ElGamal keypair
    print("Generating ElGamal keypair...")
    public_key, private_key = elgamal_keygen(bits=16)

    # User input for two integers
    num1 = int(input("Enter the first integer to encrypt: "))
    num2 = int(input("Enter the second integer to encrypt: "))

    # Encrypt the integers
    encrypted_num1 = elgamal_encrypt(public_key, num1)
    encrypted_num2 = elgamal_encrypt(public_key, num2)

    print(f"Encrypted {num1}: {encrypted_num1}")
    print(f"Encrypted {num2}: {encrypted_num2}")

    # Homomorphic multiplication
    encrypted_product = elgamal_multiply(encrypted_num1[0], encrypted_num1[1], encrypted_num2[0], encrypted_num2[1], public_key[0])
    print(f"Encrypted product: {encrypted_product}")

    # Decrypt the product
    decrypted_product = elgamal_decrypt(private_key, public_key, encrypted_product)
    print(f"Decrypted product: {decrypted_product}")
    print(f"Original product: {num1 * num2}")

if __name__ == "__main__":
    main_elgamal()
