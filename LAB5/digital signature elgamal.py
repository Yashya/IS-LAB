import random
from sympy import mod_inverse, isprime


# Generate a large prime p and generator g
def generate_elgamal_keys(key_size=512):
    # Generate a large prime p
    p = random.getrandbits(key_size)
    while not isprime(p):
        p = random.getrandbits(key_size)

    # Select a generator g (primitive root modulo p)
    g = random.randint(2, p - 2)

    # Private key: x (random number between 1 and p-2)
    x = random.randint(1, p - 2)

    # Public key: y = g^x mod p
    y = pow(g, x, p)

    return (p, g, y), x  # Public key (p, g, y) and private key x


# ElGamal signature generation
def elgamal_sign(message, private_key, public_key):
    p, g, y = public_key
    x = private_key
    m = int.from_bytes(message.encode(), 'big')  # Convert message to integer

    # Choose a random k such that gcd(k, p-1) == 1
    while True:
        k = random.randint(1, p - 2)
        if isprime(k):  # To simplify, choose k as a prime
            break

    # r = g^k mod p
    r = pow(g, k, p)

    # Compute s: s = (m - x * r) * k^-1 mod (p-1)
    k_inv = mod_inverse(k, p - 1)
    s = (k_inv * (m - x * r)) % (p - 1)

    return (r, s)


# ElGamal signature verification
def elgamal_verify(message, signature, public_key):
    p, g, y = public_key
    r, s = signature
    m = int.from_bytes(message.encode(), 'big')  # Convert message to integer

    # Compute v1 = (y^r * r^s) mod p
    v1 = (pow(y, r, p) * pow(r, s, p)) % p

    # Compute v2 = g^m mod p
    v2 = pow(g, m, p)

    # Signature is valid if v1 == v2
    return v1 == v2


# Main function to demonstrate ElGamal Digital Signature
def main():
    # Key generation
    print("Generating ElGamal key pair...")
    public_key, private_key = generate_elgamal_keys()

    # Input message
    message = input("Enter the message to sign: ")

    # Signing the message
    print("\nSigning the message...")
    signature = elgamal_sign(message, private_key, public_key)
    print(f"Signature: {signature}")

    # Verifying the signature
    print("\nVerifying the signature...")
    is_valid = elgamal_verify(message, signature, public_key)

    if is_valid:
        print("Signature is valid.")
    else:
        print("Signature is invalid.")


# Run the ElGamal signature demonstration
if __name__ == "__main__":
    main()
