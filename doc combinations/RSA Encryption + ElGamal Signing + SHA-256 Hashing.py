import random
from sympy import randprime
from hashlib import sha256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
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


# --- ElGamal Signing Functions ---
def egcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y


def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise ValueError('Modular inverse does not exist.')
    return x % m


def elgamal_keygen(bit_size=512):
    p = randprime(2 ** (bit_size - 1), 2 ** bit_size)
    g = random.randint(2, p - 1)
    x = random.randint(1, p - 2)
    y = pow(g, x, p)
    return (p, g, x, y)


def elgamal_sign(p, g, x, message):
    h = int(sha256(message.encode()).hexdigest(), 16)
    while True:
        k = random.randint(1, p - 2)
        if egcd(k, p - 1)[0] == 1:
            break
    r = pow(g, k, p)
    k_inv = modinv(k, p - 1)
    s = (k_inv * (h - x * r)) % (p - 1)
    return r, s


def elgamal_verify(p, g, y, message, r, s):
    h = int(sha256(message.encode()).hexdigest(), 16)
    v1 = pow(g, h, p)
    v2 = (pow(y, r, p) * pow(r, s, p)) % p
    return v1 == v2


# --- Menu Driven System ---
class SecureSystem:
    def __init__(self):
        self.nurse_rsa_keys = rsa_keygen()
        self.doctor_rsa_keys = rsa_keygen()
        self.nurse_elgamal_keys = elgamal_keygen()
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

        # Sign with ElGamal
        p, g, x, y = self.nurse_elgamal_keys
        self.signature = elgamal_sign(p, g, x, patient_details)
        print(f"Digital Signature: (r: {self.signature[0]}, s: {self.signature[1]})")
        self.log_event(f"Nurse signed data with ElGamal: (r: {self.signature[0]}, s: {self.signature[1]})")

    def doctor(self):
        print("\nDoctor's Role: ")

        # Decrypt with RSA
        private_key, _ = self.doctor_rsa_keys
        decrypted_data = rsa_decrypt(private_key, self.encrypted_data)
        print(f"Decrypted Data (Patient Details): {decrypted_data}")
        self.log_event(f"Doctor decrypted patient data: {decrypted_data}")

        # Verify Signature
        p, g, _, y = self.nurse_elgamal_keys
        r, s = self.signature
        valid = elgamal_verify(p, g, y, decrypted_data, r, s)
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

        # Create Message Digest using SHA-256
        if self.prescription:
            digest = sha256(self.prescription.encode()).hexdigest()
            print(f"Message Digest (SHA-256): {digest}")
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
