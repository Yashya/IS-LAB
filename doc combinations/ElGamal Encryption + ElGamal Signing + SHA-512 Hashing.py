import random
from hashlib import sha512  # Importing SHA-512
from sympy import isprime, randprime
import logging
from math import gcd

# Configure logging
logging.basicConfig(filename='system_logs.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

# --- ElGamal Encryption Functions ---
def elgamal_keygen(bit_size=2048):
    p = randprime(2 ** (bit_size - 1), 2 ** bit_size)
    g = random.randint(2, p - 1)
    x = random.randint(1, p - 2)
    y = pow(g, x, p)
    return (p, g, x, y)


def elgamal_encrypt(p, g, y, message):
    k = random.randint(1, p - 2)
    c1 = pow(g, k, p)  # c1 = g^k mod p
    c2 = (pow(y, k, p) * int.from_bytes(message.encode(), 'big')) % p  # c2 = (y^k * m) mod p
    return (c1, c2)


def elgamal_decrypt(p, x, ciphertext):
    c1, c2 = ciphertext
    m = (c2 * pow(c1, p - 1 - x, p)) % p  # m = (c2 * (c1^(p-1-x) mod p)) mod p
    return m


# --- ElGamal Signing Functions ---
def elgamal_sign(p, g, x, message):
    h = int(sha512(message.encode()).hexdigest(), 16)  # Hashing the message with SHA-512
    while True:
        k = random.randint(1, p - 2)
        if isprime(k) and (gcd(k, p - 1) == 1):
            break
    r = pow(g, k, p)
    k_inv = pow(k, -1, p - 1)
    s = (k_inv * (h - x * r)) % (p - 1)
    return r, s


def elgamal_verify(p, g, y, message, r, s):
    h = int(sha512(message.encode()).hexdigest(), 16)
    v1 = pow(g, h, p)
    v2 = (pow(y, r, p) * pow(r, s, p)) % p
    return v1 == v2


# --- Menu Driven System ---
class SecureSystem:
    def __init__(self):
        self.nurse_elgamal_keys = elgamal_keygen()
        self.doctor_elgamal_keys = elgamal_keygen()
        self.encrypted_data = None
        self.signature = None
        self.prescription = None

    def log_event(self, event):
        logging.info(event)

    def nurse(self):
        print("\nNurse's Role:")
        patient_details = input("Enter patient details: ")

        # Encrypt with ElGamal
        p, g, x, y = self.doctor_elgamal_keys
        self.encrypted_data = elgamal_encrypt(p, g, y, patient_details)
        print(f"Encrypted Data (ElGamal): {self.encrypted_data}")
        self.log_event(f"Nurse encrypted patient data: {patient_details}")

        # Sign with ElGamal
        p, g, x, _ = self.nurse_elgamal_keys
        self.signature = elgamal_sign(p, g, x, patient_details)
        print(f"Digital Signature: (r: {self.signature[0]}, s: {self.signature[1]})")
        self.log_event(f"Nurse signed data with ElGamal: (r: {self.signature[0]}, s: {self.signature[1]})")

    def doctor(self):
        print("\nDoctor's Role:")

        # Decrypt with ElGamal
        p, _, x, _ = self.doctor_elgamal_keys
        decrypted_data_int = elgamal_decrypt(p, x, self.encrypted_data)
        decrypted_data = decrypted_data_int.to_bytes((decrypted_data_int.bit_length() + 7) // 8, 'big').decode()
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
        print("\nTechnician's Role:")

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
            print("\nMenu:")
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
