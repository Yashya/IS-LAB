from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# 1. RSA Key Generation for the Doctor
def generate_rsa_keys():
    key = RSA.generate(2048)  # Generate a 2048-bit RSA key pair
    private_key = key
    public_key = key.publickey()
    return private_key, public_key

# 2. Doctor Signs the Prescription
def sign_prescription(prescription, private_key):
    # Hash the prescription message
    message_hash = SHA256.new(prescription.encode())
    # Sign the message hash using the private key
    signature = pkcs1_15.new(private_key).sign(message_hash)
    return signature

# 3. Verifier Verifies the Prescription Signature
def verify_prescription(prescription, signature, public_key):
    message_hash = SHA256.new(prescription.encode())
    try:
        # Verify the signature using the public key and message hash
        pkcs1_15.new(public_key).verify(message_hash, signature)
        return True
    except (ValueError, TypeError):
        return False

# Main function to simulate the menu-driven process
def main():
    # Step 1: Generate RSA key pair for the doctor
    doctor_private_key, doctor_public_key = generate_rsa_keys()
    print("Doctor's Public Key (for Verifier):\n", doctor_public_key.export_key().decode())

    prescription_signed = False  # To track if a prescription is signed
    prescription_message = ""
    prescription_signature = None

    while True:
        print("\n--- Prescription Management System ---")
        print("1. Doctor: Sign a Prescription")
        print("2. Verifier: Verify the Prescription")
        print("3. Patient: Receive the Prescription")
        print("4. Exit")

        choice = int(input("Enter your choice: "))

        if choice == 1:
            # Doctor signs the prescription
            prescription_message = input("Doctor, enter the prescription to be signed: ")
            prescription_signature = sign_prescription(prescription_message, doctor_private_key)
            print(f"\nPrescription: {prescription_message}")
            print(f"Prescription signed successfully!\nSignature: {prescription_signature.hex()}")
            prescription_signed = True

        elif choice == 2:
            # Verifier verifies the signed prescription
            if not prescription_signed:
                print("No prescription has been signed yet!")
            else:
                print(f"\nPrescription: {prescription_message}")
                print(f"Signature: {prescription_signature.hex()}")
                verification_result = verify_prescription(prescription_message, prescription_signature, doctor_public_key)
                if verification_result:
                    print("\nPrescription verified successfully! It is valid and signed by the doctor.")
                else:
                    print("\nVerification failed! The prescription may be tampered or not signed by the doctor.")

        elif choice == 3:
            # Patient receives the verified prescription
            if not prescription_signed:
                print("No prescription has been signed and verified yet!")
            else:
                print("\nPatient received the prescription successfully!")
                print(f"Prescription: {prescription_message}")

        elif choice == 4:
            print("Exiting the program.")
            break

        else:
            print("Invalid choice! Please select a valid option.")

# Run the program
if __name__ == "__main__":
    main()
