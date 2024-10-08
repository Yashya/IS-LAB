import random
from hashlib import sha512
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
import logging

# Configure logging
logging.basicConfig(filename='system_logs.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

# --- RSA Encryption Functions ---
def rsa_keygen(key_size=2048):  # Changed from 512 to 2048
    # Generate RSA keys
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def rsa_encrypt(public_key, message):
    # Encrypt message with RSA
    cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
    ciphertext = cipher.encrypt(message.encode())
    return ciphertext


def rsa_decrypt(private_key, ciphertext):
    # Decrypt message with RSA
    cipher = PKCS1_OAEP.new(RSA.import_key(private_key))
    decrypted_message = cipher.decrypt(ciphertext).decode()
    return decrypted_message


# --- RSA Signing Functions ---
def rsa_sign(private_key, message):
    # Sign message with RSA using SHA-512
    key = RSA.import_key(private_key)
    h = SHA512.new(message.encode())
    signature = pkcs1_15.new(key).sign(h)
    return signature


def rsa_verify(public_key, message, signature):
    # Verify the signature using RSA
    key = RSA.import_key(public_key)
    h = SHA512.new(message.encode())
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


# --- Menu Driven System ---
class SecureSystem:
    def __init__(self):
        self.nurse_rsa_keys = rsa_keygen()
        self.doctor_rsa_keys = rsa_keygen()
        self.encrypted_data = None
        self.signature = None
        self.prescription = None

    def log_event(self, event):
        logging.info(event)

    def nurse(self):
        print("\nNurse's Role: ")
        patient_details = input("Enter patient details: ")

        # Encrypt with RSA
        _, public_key = self.doctor_rsa_keys
        self.encrypted_data = rsa_encrypt(public_key, patient_details)
        print(f"Encrypted Data (RSA): {self.encrypted_data.hex()}")
        self.log_event(f"Nurse encrypted patient data: {patient_details}")

        # Sign with RSA
        private_key, _ = self.nurse_rsa_keys
        self.signature = rsa_sign(private_key, patient_details)
        print(f"Digital Signature: {self.signature.hex()}")
        self.log_event(f"Nurse signed data with RSA: {self.signature.hex()}")

    def doctor(self):
        print("\nDoctor's Role: ")

        # Decrypt with RSA
        private_key, _ = self.doctor_rsa_keys
        decrypted_data = rsa_decrypt(private_key, self.encrypted_data)
        print(f"Decrypted Data (Patient Details): {decrypted_data}")
        self.log_event(f"Doctor decrypted patient data: {decrypted_data}")

        # Verify Signature
        public_key, _ = self.nurse_rsa_keys
        valid = rsa_verify(public_key, decrypted_data, self.signature)
        if not valid:
            print("Signature verification failed.")
            self.log_event("Signature verification failed.")
            return

        print("Signature verified successfully.")
        self.log_event("Signature verified successfully.")

        # Write prescription
        self.prescription = input("Write a prescription: ")
        self.log_event(f"Doctor wrote prescription: {self.prescription}")

    def technician(self):
        print("\nTechnician's Role: ")

        # Create Message Digest using SHA-512
        if self.prescription:
            digest = sha512(self.prescription.encode()).hexdigest()
            print(f"Message Digest (SHA-512): {digest}")
            self.log_event(f"Technician created message digest: {digest}")
        else:
            print("No prescription to create a digest from.")
            self.log_event("No prescription to create a digest from.")

    def view_logs(self):
        print("\n--- Logs ---")
        with open('system_logs.txt', 'r') as file:
            logs = file.read()
            print(logs)

    def run(self):
        while True:
            print("\nMenu: ")
            print("1. Nurse")
            print("2. Doctor")
            print("3. Technician")
            print("4. View Logs")
            print("5. Exit")

            choice = input("Choose an option: ")

            if choice == '1':
                self.nurse()
            elif choice == '2':
                self.doctor()
            elif choice == '3':
                self.technician()
            elif choice == '4':
                self.view_logs()
            elif choice == '5':
                break
            else:
                print("Invalid option, try again.")


# Instantiate the system and run
system = SecureSystem()
system.run()

