import time
import hashlib
from sympy import mod_inverse
import random
from math import gcd


# Function to generate ElGamal keys
def generate_elgamal_keys():
    p = 23  # A small prime number for demonstration
    g = 5  # A generator of the multiplicative group
    private_key = random.randint(1, p - 2)
    public_key = pow(g, private_key, p)
    return private_key, public_key, p, g


# Function for ElGamal encryption
def elgamal_encrypt(public_key, p, g, message):
    y = random.randint(1, p - 2)  # Random number
    c1 = pow(g, y, p)  # c1 = g^y mod p
    c2 = (pow(public_key, y, p) * message) % p  # c2 = (y^k * m) mod p
    return c1, c2


# Function for ElGamal signing
def elgamal_sign(private_key, p, g, message):
    k = random.randint(1, p - 2)
    while gcd(k, p - 1) != 1:  # Ensure k is coprime to p-1
        k = random.randint(1, p - 2)  # Choose a new k
    k_inv = mod_inverse(k, p - 1)  # k inverse mod (p-1)
    r = pow(g, k, p)  # r = g^k mod p
    s = (k_inv * (hash_data(message) + private_key * r)) % (p - 1)  # s = k_inv * (H(m) + x * r) mod (p-1)
    return r, s


# Function to hash data using SHA-256
def hash_data(data):
    return int(hashlib.sha256(data.encode()).hexdigest(), 16)  # Return the hash as an integer


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
def perform_transaction(elgamal_private_key, elgamal_public_key, p, g):
    customer_name = input("Enter Customer Name: ")
    merchant_name = input("Enter Merchant Name: ")
    amount = input("Enter Transaction Amount: ")
    transaction_details = f"{customer_name} paid {amount} to {merchant_name}"

    # Encrypt transaction details using ElGamal
    transaction_amount = int(amount)  # Convert amount to integer for encryption
    c1, c2 = elgamal_encrypt(elgamal_public_key, p, g, transaction_amount)
    print(f"Encrypted Transaction (ElGamal): c1={c1}, c2={c2}")

    # Sign the transaction details using ElGamal
    r, s = elgamal_sign(elgamal_private_key, p, g, transaction_details)

    # Hash the transaction details
    transaction_hash = hash_data(transaction_details)

    # Log the transaction with a timestamp
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    transaction_log.append({
        "timestamp": timestamp,
        "transaction_hash": transaction_hash,
        "signature": (r, s)  # Store signature as a tuple
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
    elgamal_private_key, elgamal_public_key, p, g = generate_elgamal_keys()
    while True:
        choice = menu()
        if choice == '1':
            perform_transaction(elgamal_private_key, elgamal_public_key, p, g)
        elif choice == '2':
            view_transaction_log()
        elif choice == '3':
            print("Exiting the program.")
            break
        else:
            print("Invalid choice! Please try again.")


if __name__ == "__main__":
    main()
