import time
import random
from Crypto.Util import number
from hashlib import sha512


# RSA Functions
def generate_rsa_keys():
    p = number.getPrime(512)
    q = number.getPrime(512)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = 65537  # Common choice for e
    d = pow(e, -1, phi_n)
    return (e, n), (d, n)


def rsa_encrypt(public_key, plaintext):
    e, n = public_key
    return pow(plaintext, e, n)


def rsa_decrypt(private_key, ciphertext):
    d, n = private_key
    return pow(ciphertext, d, n)


# ElGamal Functions
def generate_elgamal_keys():
    p = number.getPrime(512)
    g = random.randint(2, p - 1)
    x = random.randint(1, p - 2)  # Private key
    y = pow(g, x, p)  # Public key
    return (p, g, y), x  # Return public key and private key


def elgamal_encrypt(public_key, plaintext):
    p, g, y = public_key
    k = random.randint(1, p - 2)
    c1 = pow(g, k, p)
    c2 = (plaintext * pow(y, k, p)) % p
    return c1, c2


def elgamal_sign(private_key, message):
    p, g, x = private_key  # Unpack private key correctly
    k = random.randint(1, p - 2)
    r = pow(g, k, p)
    k_inv = pow(k, -1, p - 1)
    s = (k_inv * (message - x * r)) % (p - 1)
    return r, s


def elgamal_verify(public_key, message, signature):
    p, g, y = public_key
    r, s = signature
    if not (1 <= r < p) or not (1 <= s < p - 1):
        return False
    left = (pow(y, r, p) * pow(r, s, p)) % p
    right = pow(g, message, p)
    return left == right


# Hash Function
def hash_transaction(transaction):
    return sha512(transaction.encode()).hexdigest()


# Transaction Log
transaction_log = []


def log_transaction(hash_value):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    transaction_log.append((hash_value, timestamp))


# Main Program
def main():
    public_key, private_key = generate_rsa_keys()
    elgamal_public_key, elgamal_private_key = generate_elgamal_keys()

    while True:
        print("\nMenu:")
        print("1. Customer Transaction")
        print("2. View Transaction Log (Auditor)")
        print("3. Exit")
        choice = input("Choose an option: ")

        if choice == '1':
            amount_str = input("Enter transaction amount: ").strip()  # Strip any whitespace
            try:
                # Attempt to convert to float first, then to int in cents
                amount = float(amount_str)

                # Multiply by 100 to handle precision
                amount_in_cents = int(amount * 100)  # Convert to cents

                # Hash the transaction
                transaction_hash = hash_transaction(amount_str)

                # RSA Encryption
                encrypted_amount = rsa_encrypt(public_key, amount_in_cents)

                # ElGamal Signing
                signature = elgamal_sign((elgamal_public_key[0], elgamal_public_key[1], elgamal_private_key),
                                         amount_in_cents)

                # Log the transaction
                log_transaction(transaction_hash)

                print(f"Transaction Amount (Encrypted): {encrypted_amount}")
                print(f"Transaction Hash: {transaction_hash}")
                print(f"ElGamal Signature: {signature}")

            except ValueError:
                print("Invalid amount. Please enter a numeric value.")

        elif choice == '2':
            print("\nTransaction Log:")
            for hash_value, timestamp in transaction_log:
                print(f"Hash: {hash_value}, Timestamp: {timestamp}")

        elif choice == '3':
            print("Exiting the program.")
            break

        else:
            print("Invalid choice. Please choose again.")


if __name__ == "__main__":
    main()
