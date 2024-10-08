import random
from hashlib import sha512  # Importing SHA-512
from sympy import isprime, randprime
import logging
from math import gcd

# Configure logging
logging.basicConfig(filename='system_logs.txt', level=logging.INFO, format='%(asctime)s - %(message)s')


# --- Rabin Encryption Functions ---
def rabin_keygen(bit_size=2048):
    p = randprime(2 ** (bit_size // 2 - 1), 2 ** (bit_size // 2))
    q = randprime(2 ** (bit_size // 2 - 1), 2 ** (bit_size // 2))
    n = p * q
    return p, q, n


def rabin_encrypt(n, message):
    m = int.from_bytes(message.encode(), 'big')  # Convert message to integer
    r = random.randint(1, n - 1)
    c = (r * r) % n
    return c


def rabin_decrypt(p, q, c):
    n = p * q
    r1 = pow(c, (p + 1) // 4, p)  # r1 = c^((p+1)/4) mod p
    r2 = (p - r1) % p
    r3 = pow(c, (q + 1) // 4, q)  # r3 = c^((q+1)/4) mod q
    r4 = (q - r3) % q

    # Chinese Remainder Theorem to combine results
    return [
        ((r1, r3), (r1, r4), (r2, r3), (r2, r4))
    ]


# --- RSA Signing Functions ---
def rsa_keygen(bit_size=2048):
    p = randprime(2 ** (bit_size // 2 - 1), 2 ** (bit_size // 2))
    q = randprime(2 ** (bit_size // 2 - 1), 2 ** (bit_size // 2))
    n = p * q
    phi_n = (p - 1) * (q - 1)

    e = 65537  # Commonly used prime exponent
    d = pow(e, -1, phi_n)  # Modular inverse
    return (n, e, d)


def rsa_sign(n, d, message):
    h = int(sha512(message.encode()).hexdigest(), 16)  # Hashing the message with SHA-512
    signature = pow(h, d, n)  # Signature = h^d mod n
    return signature


def rsa_verify(n, e, message, signature):
    h = int(sha512(message.encode()).hexdigest(), 16)
    verified_hash = pow(signature, e, n)  # h' = signature^e mod n
    return h == verified_hash


# --- Menu Driven System ---
class SecureSystem:
    def __init__(self):
        self.rabin_keys = rabin_keygen()
        self.rsa_keys = rsa_keygen()
        self.encrypted_data = None
        self.signature = None
        self.prescription = None

    def log_event(self, event):
        logging.info(event)

    def nurse(self):
        print("\nNurse's Role:")
        patient_details = input("Enter patient details: ")

        # Encrypt with Rabin
        p, q, n = self.rabin_keys
        self.encrypted_data = rabin_encrypt(n, patient_details)
        print(f"Encrypted Data (Rabin): {self.encrypted_data}")
        self.log_event(f"Nurse encrypted patient data: {patient_details}")

        # Sign with RSA
        n_rsa, e, d = self.rsa_keys
        self.signature = rsa_sign(n_rsa, d, patient_details)
        print(f"Digital Signature (RSA): {self.signature}")
        self.log_event(f"Nurse signed data with RSA: {self.signature}")

    def doctor(self):
        print("\nDoctor's Role:")

        # Decrypt with Rabin
        p, q, n = self.rabin_keys
        decrypted_data_options = rabin_decrypt(p, q, self.encrypted_data)

        # Attempt to decode each decrypted option
        for r in decrypted_data_options[0]:
            try:
                decrypted_data = r[0].to_bytes((r[0].bit_length() + 7) // 8, 'big').decode('utf-8')
                print(f"Decrypted Data (Patient Details): {decrypted_data}")
                self.log_event(f"Doctor decrypted patient data: {decrypted_data}")

                # Verify Signature
                n_rsa, e, d = self.rsa_keys
                valid = rsa_verify(n_rsa, e, decrypted_data, self.signature)
                if valid:
                    print("Signature verified successfully.")
                    self.log_event("Signature verified successfully.")
                else:
                    print("Signature verification failed.")
                    self.log_event("Signature verification failed.")
                break  # Exit loop after successful decryption
            except (UnicodeDecodeError, OverflowError):
                continue  # Try the next option if decoding fails

        else:
            print("All decryption attempts failed.")
            self.log_event("All decryption attempts failed.")

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
