import time
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512

# Function to generate RSA keys
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Function to encrypt data using RSA
def encrypt_rsa(data, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    encrypted_data = cipher.encrypt(data.encode())
    return encrypted_data

# Function to sign data using RSA
def sign_data_rsa(private_key, data):
    rsa_key = RSA.import_key(private_key)
    h = SHA512.new(data.encode())  # Hash the data using SHA-512
    signature = pkcs1_15.new(rsa_key).sign(h)
    return signature

# Function to hash data using SHA-512
def hash_data(data):
    return hashlib.sha512(data.encode()).hexdigest()

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
def perform_transaction(rsa_private_key, rsa_public_key):
    customer_name = input("Enter Customer Name: ")
    merchant_name = input("Enter Merchant Name: ")
    amount = input("Enter Transaction Amount: ")

    transaction_details = f"{customer_name} paid {amount} to {merchant_name}"

    # Encrypt transaction details using RSA
    encrypted_transaction = encrypt_rsa(transaction_details, rsa_public_key)
    print(f"Encrypted Transaction: {encrypted_transaction.hex()}")  # Display encrypted data in hex

    # Hash the transaction details using SHA-512
    transaction_hash = hash_data(transaction_details)

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
    rsa_private_key, rsa_public_key = generate_rsa_keys()  # Generate RSA keys
    while True:
        choice = menu()
        if choice == '1':
            perform_transaction(rsa_private_key, rsa_public_key)
        elif choice == '2':
            view_transaction_log()
        elif choice == '3':
            print("Exiting the program.")
            break
        else:
            print("Invalid choice! Please try again.")

if __name__ == "__main__":
    main()
