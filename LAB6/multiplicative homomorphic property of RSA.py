import random
from math import gcd

def generate_prime_candidate(length):
    """Generate an odd prime number randomly."""
    p = random.getrandbits(length)
    # Ensure p is odd
    p |= (1 << length - 1) | 1
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
    while not is_probable_prime(p, 5):
        p = generate_prime_candidate(length)
    return p

def generate_rsa_keypair(bits=512):
    """Generate RSA keypair (public and private keys)."""
    p = generate_prime_number(bits)
    q = generate_prime_number(bits)

    n = p * q
    phi_n = (p - 1) * (q - 1)

    # Choose e such that 1 < e < phi_n and gcd(e, phi_n) == 1
    e = 65537  # Common choice for e
    d = pow(e, -1, phi_n)  # Compute d using the modular inverse

    return (e, n), (d, n)  # public key, private key

def encrypt(public_key, plaintext):
    """Encrypt plaintext using the public key."""
    e, n = public_key
    ciphertext = pow(plaintext, e, n)
    return ciphertext

def multiply_encrypted(c1, c2, n):
    """Multiply two ciphertexts without decrypting them."""
    return (c1 * c2) % n

def decrypt(private_key, ciphertext):
    """Decrypt ciphertext using the private key."""
    d, n = private_key
    plaintext = pow(ciphertext, d, n)
    return plaintext

def main():
    # Generate RSA keypair
    print("Generating RSA keypair...")
    public_key, private_key = generate_rsa_keypair(bits=16)  # Using smaller bit size for demonstration

    # Define two integers to encrypt
    integer1 = 7
    integer2 = 3

    # Encrypt the integers
    ciphertext1 = encrypt(public_key, integer1)
    ciphertext2 = encrypt(public_key, integer2)

    print(f"Ciphertext of {integer1}: {ciphertext1}")
    print(f"Ciphertext of {integer2}: {ciphertext2}")

    # Perform multiplication on the encrypted integers
    encrypted_product = multiply_encrypted(ciphertext1, ciphertext2, public_key[1])
    print(f"Encrypted product of {integer1} and {integer2}: {encrypted_product}")

    # Decrypt the result of the multiplication
    decrypted_product = decrypt(private_key, encrypted_product)
    print(f"Decrypted product: {decrypted_product}")
    print(f"Original product: {integer1 * integer2}")

if __name__ == "__main__":
    main()
