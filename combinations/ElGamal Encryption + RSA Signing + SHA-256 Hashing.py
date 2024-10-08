import time
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from random import getrandbits
from sympy import mod_inverse

# ElGamal encryption functions
def generate_elgamal_keys(p, g):
    x = getrandbits(2048)  # Private key
    y = pow(g, x, p)  # Public key
    return (p, g, y), x

def elgamal_encrypt(public_key, plaintext):
    p, g, y = public_key
    k = getrandbits(2048)  # Randomly chosen k
    k_inv = mod_inverse(k, p - 1)
    c1 = pow(g, k, p)  # First part of ciphertext
    c2 = (pow(y, k, p) * int.from_bytes(plaintext.encode(), 'big')) % p  # Second part of ciphertext
    return c1, c2

def elgamal_decrypt(private_key, ciphertext):
    p, g, y = private_key
    c1, c2 = ciphertext
    x = private_key[1]  # x is the private key
    s = pow(c1, x, p)  # Shared secret
    s_inv = mod_inverse(s, p)
    decrypted = (c2 * s_inv) % p
    return decrypted.to_bytes((decrypted.bit_length() + 7) // 8, 'big').decode()  # Convert to bytes and decode

# Function to generate RSA keys
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Function to sign data using RSA
def sign_data_rsa(private_key, data):
    rsa_key = RSA.import_key(private_key)
    h = SHA256.new(data.encode())  # Hash the data using SHA-256
    signature = pkcs1_15.new(rsa_key).sign(h)
    return signature

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
def perform_transaction(rsa_private_key, rsa_public_key, elgamal_public_key):
    customer_name = input("Enter Customer Name: ")
    merchant_name = input("Enter Merchant Name: ")
    amount = input("Enter Transaction Amount: ")

    transaction_details = f"{customer_name} paid {amount} to {merchant_name}"

    # Encrypt transaction details using ElGamal
    c1, c2 = elgamal_encrypt(elgamal_public_key, transaction_details)
    print(f"Encrypted Transaction (ElGamal): c1={c1}, c2={c2}")  # Display ElGamal encrypted data

    # Hash the transaction details using SHA-256
    transaction_hash = hashlib.sha256(transaction_details.encode()).hexdigest()

    # Sign the transaction hash using RSA
    signature = sign_data_rsa(rsa_private_key, transaction_hash)

    # Log the transaction with a timestamp
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    transaction_log.append({
        "timestamp": timestamp,
        "transaction_hash": transaction_hash,
        "signature": signature.hex()  # Store signature in hex format
    })

    print("Transaction Completed Successfully!")
    print(f"Transaction Hash: {transaction_hash}")
    print(f"Signature: {signature.hex()}")  # Display signature in hex

# Function to view transaction log
def view_transaction_log():
    if not transaction_log:
        print("No transactions found.")
        return
    for entry in transaction_log:
        print(f"Timestamp: {entry['timestamp']}, Transaction Hash: {entry['transaction_hash']}, Signature: {entry['signature']}")

# Main function to run the program
def main():
    # Generate ElGamal keys
    p = 23  # Example prime number
    g = 5   # Example generator
    elgamal_public_key, elgamal_private_key = generate_elgamal_keys(p, g)  # Generate ElGamal keys

    # Generate RSA keys
    rsa_private_key, rsa_public_key = generate_rsa_keys()  # Generate RSA keys

    while True:
        choice = menu()
        if choice == '1':
            perform_transaction(rsa_private_key, rsa_public_key, elgamal_public_key)
        elif choice == '2':
            view_transaction_log()
        elif choice == '3':
            print("Exiting the program.")
            break
        else:
            print("Invalid choice! Please try again.")

if __name__ == "__main__":
    main()
