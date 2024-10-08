import time
import hashlib
import random


# Function to generate ElGamal keys
def generate_elgamal_keys(p, g):
    private_key = random.randint(1, p - 2)  # Private key x
    public_key = pow(g, private_key, p)  # Public key y = g^x mod p
    return private_key, public_key


# Function to sign data using ElGamal
def sign_data_elgamal(private_key, data, p, g):
    k = random.randint(1, p - 2)  # Random integer k
    r = pow(g, k, p)  # r = g^k mod p
    k_inv = pow(k, p - 2, p)  # k^-1 mod p (using Fermat's little theorem)

    h = int(hashlib.sha512(data.encode()).hexdigest(), 16)  # Hash the data to an integer
    s = (k_inv * (h + private_key * r)) % (p - 1)  # s = k^-1 * (h + x * r) mod (p - 1)

    return r, s  # Signature is the pair (r, s)


# Function to verify ElGamal signature
def verify_signature_elgamal(public_key, data, signature, p, g):
    r, s = signature
    if not (0 < r < p and 0 < s < p - 1):
        return False  # Invalid signature

    h = int(hashlib.sha512(data.encode()).hexdigest(), 16)  # Hash the data to an integer
    v1 = (pow(public_key, r, p) * pow(r, s, p)) % p  # v1 = y^r * r^s mod p
    v2 = pow(g, h, p)  # v2 = g^h mod p

    return v1 == v2  # If both are equal, the signature is valid


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

    # Hash the transaction details
    transaction_hash = hashlib.sha512(transaction_details.encode()).hexdigest()

    # Sign the original transaction details using ElGamal
    signature = sign_data_elgamal(elgamal_private_key, transaction_details, p, g)

    # Log the transaction with a timestamp
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    transaction_log.append({
        "timestamp": timestamp,
        "transaction_hash": transaction_hash,
        "signature": signature  # Store the signature as a pair
    })

    print("Transaction Completed Successfully!")
    print(f"Transaction Hash: {transaction_hash}")
    print(f"Signature: {signature}")  # Display signature as a pair


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
    # Example parameters for ElGamal
    p = 23  # A prime number
    g = 5  # A primitive root mod p

    elgamal_private_key, elgamal_public_key = generate_elgamal_keys(p, g)
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
