import time
import hashlib
import random
from sympy import isprime, mod_inverse
from math import gcd


# Function to generate Rabin keys
def generate_rabin_keys():
    p = 61  # A prime number
    q = 53  # Another prime number
    n = p * q
    return (p, q, n)


# Function to perform Rabin encryption
def rabin_encrypt(n, message):
    m = message % n
    k = random.randint(1, n - 1)
    while gcd(k, n) != 1:
        k = random.randint(1, n - 1)
    c = (pow(k, 2, n) * m) % n  # Rabin Encryption: c = k^2 * m mod n
    return c


# Function to generate ElGamal keys
def generate_elgamal_keys():
    p = 23  # A prime number
    g = 5  # A primitive root modulo p
    x = random.randint(1, p - 2)  # Private key
    y = pow(g, x, p)  # Public key
    return (p, g, x, y)  # Returns (p, g, private_key, public_key)


# Function for ElGamal signing
def elgamal_sign(private_key, p, g, message):
    x = private_key
    k = random.randint(1, p - 2)
    while gcd(k, p - 1) != 1:
        k = random.randint(1, p - 2)

    r = pow(g, k, p)  # r = g^k mod p
    k_inv = mod_inverse(k, p - 1)  # k inverse mod (p-1)
    s = (k_inv * (hash_data(message) + x * r)) % (p - 1)  # s = k^(-1) * (H(m) + x * r) mod (p - 1)
    return (r, s)


# Function to hash data using SHA-512
def hash_data(data):
    return int(hashlib.sha512(data.encode()).hexdigest(), 16)  # Return the hash as an integer


# Log to keep track of transactions
transaction_log = []


# Main menu
def menu():
    print("\n--- Customer-Merchant Transaction System ---")
    print("1. Perform a Transaction")
    print("2. View Transaction Log")
    print("3. Exit")
    choice = input("Enter your choice: ")
    return choice


# Function to perform a transaction
def perform_transaction(rabin_n, elgamal_private_key):
    customer_name = input("Enter Customer Name: ")
    merchant_name = input("Enter Merchant Name: ")
    amount = input("Enter Transaction Amount: ")
    transaction_details = f"{customer_name} paid {amount} to {merchant_name}"

    # Encrypt transaction details using Rabin
    transaction_amount = int(amount)  # Convert amount to integer for encryption
    c = rabin_encrypt(rabin_n, transaction_amount)
    print(f"Encrypted Transaction (Rabin): c={c}")

    # Sign the transaction hash using ElGamal
    r, s = elgamal_sign(elgamal_private_key[2], elgamal_private_key[0], elgamal_private_key[1], transaction_details)

    # Hash the transaction details
    transaction_hash = hash_data(transaction_details)

    # Log the transaction with a timestamp
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    transaction_log.append({
        "timestamp": timestamp,
        "transaction_hash": transaction_hash,
        "signature": (r, s)
    })

    print("Transaction Completed Successfully!")
    print(f"Transaction Hash: {transaction_hash}")
    print(f"Signature: (r={r}, s={s})")


# Function to view transaction log
def view_transaction_log():
    if not transaction_log:
        print("No transactions found.")
        return
    for entry in transaction_log:
        print(
            f"Timestamp: {entry['timestamp']}, Transaction Hash: {entry['transaction_hash']}, Signature: (r={entry['signature'][0]}, s={entry['signature'][1]})")


# Main function to run the program
def main():
    rabin_p, rabin_q, rabin_n = generate_rabin_keys()
    elgamal_keys = generate_elgamal_keys()

    while True:
        choice = menu()
        if choice == '1':
            perform_transaction(rabin_n, elgamal_keys)  # Pass all ElGamal keys
        elif choice == '2':
            view_transaction_log()
        elif choice == '3':
            print("Exiting the program.")
            break
        else:
            print("Invalid choice! Please try again.")


if __name__ == "__main__":
    main()
