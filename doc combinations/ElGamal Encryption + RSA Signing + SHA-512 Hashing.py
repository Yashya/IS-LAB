import random
import logging
from sympy import isprime, randprime
from hashlib import sha512, sha256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512


# --- ElGamal Encryption Functions ---
def elgamal_keygen(bit_size=512):
    p = randprime(2 ** (bit_size - 1), 2 ** bit_size)
    g = random.randint(2, p - 1)
    x = random.randint(1, p - 2)
    y = pow(g, x, p)
    return (p, g, x, y)


def elgamal_encrypt(p, g, y, message):


    k = random.randint(1, p - 2)
    c1 = pow(g, k, p)  # c1 = g^k mod p
    c2 = (pow(y, k, p) * int.from_bytes(message.encode(), 'big')) % p  # c2 = y^k * m mod p
    return c1, c2


def elgamal_decrypt(p, x, ciphertext):

    c1, c2 = ciphertext
    s = pow(c1, x, p)  # s = c1^x mod p
    m = (c2 * modinv(s, p)) % p  # m = c2 * s^-1 mod p
    return m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()


# --- RSA Signing Functions ---
def rsa_keygen(bit_size=2048):

    key = RSA.generate(bit_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def rsa_sign(private_key, message):

    rsa_key = RSA.import_key(private_key)
    hash_obj = SHA512.new(message.encode())
    signature = pkcs1_15.new(rsa_key).sign(hash_obj)
    return signature


def rsa_verify(public_key, message, signature):

    rsa_key = RSA.import_key(public_key)
    hash_obj = SHA512.new(message.encode())
    try:
        pkcs1_15.new(rsa_key).verify(hash_obj, signature)
        return True
    except (ValueError, TypeError):
        return False


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


def create_digest(message):

    return sha512(message.encode()).hexdigest()


# --- Menu Driven System ---
class SecureSystem:
    def __init__(self):
        # Configure logging
        logging.basicConfig(filename='secure_system.log', level=logging.INFO, format='%(asctime)s - %(message)s')
        logging.info('Secure system initialized.')

        # Key generation
        self.nurse_elgamal_keys = elgamal_keygen()
        self.doctor_elgamal_keys = elgamal_keygen()
        self.nurse_rsa_key, self.nurse_rsa_pub_key = rsa_keygen()
        self.doctor_rsa_key, self.doctor_rsa_pub_key = rsa_keygen()

        self.encrypted_data = None
        self.signature = None
        self.prescription = None

    def nurse(self):
        logging.info("Nurse role activated.")
        patient_details = input("Enter patient details: ")

        # Encrypt with ElGamal
        p, g, _, y = self.doctor_elgamal_keys
        self.encrypted_data = elgamal_encrypt(p, g, y, patient_details)
        logging.info(f"Encrypted Data: {self.encrypted_data}")

        # Sign with RSA
        self.signature = rsa_sign(self.nurse_rsa_key, str(self.encrypted_data))
        logging.info(f"Digital Signature: {self.signature.hex()}")

        # Show encrypted data and signature to the nurse
        print(f"Encrypted Data: {self.encrypted_data}")
        print(f"Digital Signature: {self.signature.hex()}")

    def doctor(self):
        logging.info("Doctor role activated.")

        # Verify Signature
        valid = rsa_verify(self.nurse_rsa_pub_key, str(self.encrypted_data), self.signature)
        if not valid:
            print("Signature verification failed.")
            logging.warning("Signature verification failed.")
            return

        print("Signature verified successfully.")
        logging.info("Signature verified successfully.")

        # Decrypt with ElGamal
        p, g, x, _ = self.doctor_elgamal_keys
        decrypted_data = elgamal_decrypt(p, x, self.encrypted_data)
        print(f"Decrypted Data (Patient Details): {decrypted_data}")

        # Write prescription
        self.prescription = input("Write a prescription: ")
        logging.info(f"Prescription written: {self.prescription}")

    def technician(self):
        logging.info("Technician role activated.")

        # Create Message Digest using SHA-512
        if self.prescription:
            digest = create_digest(self.prescription)
            print(f"Message Digest (SHA-512): {digest}")
            logging.info(f"Message Digest created: {digest}")
        else:
            print("No prescription to create a digest from.")
            logging.warning("No prescription available for digest.")

    def view_logs(self):
        logging.info("Log view activated.")
        print("\nLog Contents:")
        with open('secure_system.log', 'r') as log_file:
            for line in log_file:
                print(line.strip())

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
                # Nurse takes patient details, encrypts, and signs
                self.nurse()
            elif choice == '2':
                # Doctor verifies, decrypts, and writes prescription
                self.doctor()
            elif choice == '3':
                # Technician creates a message digest and sends to the doctor
                self.technician()
            elif choice == '4':
                # View the logs
                self.view_logs()
            elif choice == '5':
                logging.info("Exiting the system.")
                break
            else:
                print("Invalid option, try again.")


# Instantiate the system and run
if __name__ == "__main__":
    system = SecureSystem()
    system.run()
