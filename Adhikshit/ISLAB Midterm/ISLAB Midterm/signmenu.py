from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
import random
import hashlib


# 1. RSA Key Generation
def generate_rsa_keys():
    key = RSA.generate(2048)  # Generate a 2048-bit RSA key pair
    private_key = key
    public_key = key.publickey()
    return private_key, public_key


# 2. RSA Signing Function
def rsa_sign(message, private_key):
    message_hash = SHA256.new(message)  # Hash the message
    signature = pkcs1_15.new(private_key).sign(message_hash)  # Sign the message hash
    return signature


# 3. RSA Verification Function
def rsa_verify(message, signature, public_key):
    message_hash = SHA256.new(message)
    try:
        pkcs1_15.new(public_key).verify(message_hash, signature)  # Verify the signature
        return True
    except (ValueError, TypeError):
        return False


# 4. ElGamal Key Generation
def generate_elgamal_keys():
    p = getPrime(256)  # Large prime number
    g = random.randint(2, p - 1)  # Generator
    x = random.randint(1, p - 2)  # Private key
    h = pow(g, x, p)  # Public key
    return p, g, h, x


# 5. ElGamal Signing Function
def elgamal_sign(message, p, g, x):
    while True:
        k = random.randint(1, p - 2)  # Random ephemeral key
        if inverse(k, p - 1) is not None:  # Ensure `k` has an inverse
            break

    r = pow(g, k, p)  # Compute r = g^k mod p
    m = bytes_to_long(message)  # Convert message to a long integer
    s = (m - x * r) * inverse(k, p - 1) % (p - 1)  # Compute s
    return (r, s)


# 6. ElGamal Verification Function
def elgamal_verify(message, r, s, p, g, h):
    if not (0 < r < p):
        return False
    m = bytes_to_long(message)
    v1 = pow(g, m, p)  # v1 = g^m mod p
    v2 = (pow(h, r, p) * pow(r, s, p)) % p  # v2 = (h^r * r^s) mod p
    return v1 == v2


# Main function with menu-driven options
def main():
    # Generate RSA and ElGamal keys
    rsa_private_key, rsa_public_key = generate_rsa_keys()
    p, g, h, x = generate_elgamal_keys()

    print("RSA and ElGamal Digital Signature Program")
    print("RSA Public Key:\n", rsa_public_key.export_key().decode())
    print("ElGamal Public Key (p, g, h):", (p, g, h))
    print("ElGamal Private Key (x):", x)

    while True:
        print("\n--- Digital Signature Menu ---")
        print("1. Sign a Message using RSA")
        print("2. Verify a Message using RSA")
        print("3. Sign a Message using ElGamal")
        print("4. Verify a Message using ElGamal")
        print("5. Exit")

        choice = int(input("Enter your choice: "))

        if choice == 1:
            # RSA Signing Operation
            message = input("Enter the message to be signed using RSA: ").encode()
            signature = rsa_sign(message, rsa_private_key)
            print(f"\nMessage: {message.decode()}")
            print(f"RSA Signature: {signature.hex()}")

        elif choice == 2:
            # RSA Verification Operation
            message = input("Enter the message to be verified using RSA: ").encode()
            signature_input = input("Enter the RSA signature in hexadecimal: ")
            try:
                signature = bytes.fromhex(signature_input)
                verification_result = rsa_verify(message, signature, rsa_public_key)
                if verification_result:
                    print("\nRSA Signature verified successfully! The message is authentic.")
                else:
                    print("\nRSA Signature verification failed! The message may be tampered.")
            except ValueError:
                print("Invalid signature format. Please enter a valid hexadecimal signature.")

        elif choice == 3:
            # ElGamal Signing Operation
            message = input("Enter the message to be signed using ElGamal: ").encode()
            r, s = elgamal_sign(message, p, g, x)
            print(f"\nMessage: {message.decode()}")
            print(f"ElGamal Signature: (r: {r}, s: {s})")

        elif choice == 4:
            # ElGamal Verification Operation
            message = input("Enter the message to be verified using ElGamal: ").encode()
            try:
                r = int(input("Enter the value of r: "))
                s = int(input("Enter the value of s: "))
                verification_result = elgamal_verify(message, r, s, p, g, h)
                if verification_result:
                    print("\nElGamal Signature verified successfully! The message is authentic.")
                else:
                    print("\nElGamal Signature verification failed! The message may be tampered.")
            except ValueError:
                print("Invalid input for r or s. Please enter integer values.")

        elif choice == 5:
            print("Exiting the program.")
            break

        else:
            print("Invalid choice! Please select a valid option.")


# Run the program
if __name__ == "__main__":
    main()
