from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# 1. RSA Key Generation
def generate_rsa_keys():
    key = RSA.generate(2048)  # Generate a 2048-bit RSA key pair
    private_key = key
    public_key = key.publickey()
    return private_key, public_key

# 2. Signing the Message
def rsa_sign(message, private_key):
    # Hash the message
    message_hash = SHA256.new(message)
    # Sign the message hash using the private key
    signature = pkcs1_15.new(private_key).sign(message_hash)
    return signature

# 3. Verifying the Signature
def rsa_verify(message, signature, public_key):
    message_hash = SHA256.new(message)
    try:
        # Verify the signature using the public key and message hash
        pkcs1_15.new(public_key).verify(message_hash, signature)
        return True
    except (ValueError, TypeError):
        return False

# Main function to simulate the signing and verification process
def main():
    # Generate RSA key pair
    private_key, public_key = generate_rsa_keys()
    print("RSA Public Key:\n", public_key.export_key().decode())
    print("RSA Private Key:\n", private_key.export_key().decode())

    while True:
        print("\n--- RSA Digital Signature ---")
        print("1. Sign a Message")
        print("2. Verify a Message")
        print("3. Exit")

        choice = int(input("Enter your choice: "))

        if choice == 1:
            # Signing Operation
            message = input("Enter the message to be signed: ").encode()
            signature = rsa_sign(message, private_key)
            print(f"\nMessage: {message.decode()}")
            print(f"Signature: {signature.hex()}")

        elif choice == 2:
            # Verification Operation
            message = input("Enter the message to be verified: ").encode()
            signature_input = input("Enter the signature in hexadecimal: ")
            try:
                # Convert the signature back to bytes
                signature = bytes.fromhex(signature_input)
                verification_result = rsa_verify(message, signature, public_key)
                if verification_result:
                    print("\nSignature verified successfully! The message is authentic.")
                else:
                    print("\nSignature verification failed! The message may be tampered.")
            except ValueError:
                print("Invalid signature format. Please enter a valid hexadecimal signature.")

        elif choice == 3:
            print("Exiting the program.")
            break

        else:
            print("Invalid choice! Please select a valid option.")

# Run the program
if __name__ == "__main__":
    main()
