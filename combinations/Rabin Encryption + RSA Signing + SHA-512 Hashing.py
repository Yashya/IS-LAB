import time
import hashlib
import random
from sympy import isprime, mod_inverse
from math import gcd  # Import gcd from the math module


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


# Function to generate RSA keys
def generate_rsa_keys():
    p = 61  # A prime number
    q = 53  # Another prime number
    n = p * q
    phi_n = (p - 1) * (q - 1)

    # Choose e such that 1 < e < phi_n and gcd(e, phi_n) = 1
    e = 17
    d = mod_inverse(e, phi_n)  # d is the modular multiplicative inverse of e
    return (d, e, n)


# Function for RSA signing
def rsa_sign(private_key, message):
    d, n = private_key
    return pow(message, d, n)  # Signature: s = H(m)^d mod n


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
def perform_transaction(rabin_n, rsa_private_key, rsa_public_key):
    customer_name = input("Enter Customer Name: ")
    merchant_name = input("Enter Merchant Name: ")
    amount = input("Enter Transaction Amount: ")
    transaction_details = f"{customer_name} paid {amount} to {merchant_name}"

    # Encrypt transaction details using Rabin
    transaction_amount = int(amount)  # Convert amount to integer for encryption
    c = rabin_encrypt(rabin_n, transaction_amount)
    print(f"Encrypted Transaction (Rabin): c={c}")

    # Hash the transaction details
    transaction_hash = hash_data(transaction_details)

    # Sign the hash of the transaction details using RSA
    signature = rsa_sign(rsa_private_key, transaction_hash)

    # Log the transaction with a timestamp
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    transaction_log.append({
        "timestamp": timestamp,
        "transaction_hash": transaction_hash,
        "signature": signature
    })

    print("Transaction Completed Successfully!")
    print(f"Transaction Hash: {transaction_hash}")
    print(f"Signature: {signature}")


# Function to view transaction log
def view_transaction_log():
    if not transaction_log:
        print("No transactions found.")
        return
    for entry in transaction_log:
        print(
            f"Timestamp: {entry['timestamp']}, Transaction Hash: {entry['transaction_hash']}, Signature: {entry['signature']}")


# Main function to run the program
def main():
    rabin_p, rabin_q, rabin_n = generate_rabin_keys()
    rsa_private_key, rsa_public_key, rsa_n = generate_rsa_keys()

    while True:
        choice = menu()
        if choice == '1':
            perform_transaction(rabin_n, (rsa_private_key, rsa_n), rsa_public_key)
        elif choice == '2':
            view_transaction_log()
        elif choice == '3':
            print("Exiting the program.")
            break
        else:
            print("Invalid choice! Please try again.")


if __name__ == "__main__":
    main()
