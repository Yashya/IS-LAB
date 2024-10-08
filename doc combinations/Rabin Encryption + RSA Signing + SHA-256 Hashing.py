import random
from sympy import randprime
from hashlib import sha256

# --- Rabin Encryption Functions ---
def rabin_keygen(bit_size=512):
    # Generate two large primes p and q
    p = randprime(2 ** (bit_size // 2 - 1), 2 ** (bit_size // 2))
    q = randprime(2 ** (bit_size // 2 - 1), 2 ** (bit_size // 2))
    n = p * q
    return (p, q, n)

def rabin_encrypt(n, message):
    m = int.from_bytes(message.encode(), 'big')  # Convert string to integer
    return (m * m) % n

def rabin_decrypt(p, q, n, ciphertext):
    # Decrypt the message using Rabin decryption
    mp = pow(ciphertext, (p + 1) // 4, p)
    mq = pow(ciphertext, (q + 1) // 4, q)

    # Use Chinese Remainder Theorem to find four potential solutions
    yp = q * modinv(q, p)
    yq = p * modinv(p, q)

    # Four possible roots
    r1 = (mp * yp + mq * yq) % n
    r2 = (mp * yp - mq * yq) % n
    r3 = (-mp * yp + mq * yq) % n
    r4 = (-mp * yp - mq * yq) % n

    # Try converting each root to a valid string
    possible_roots = [r1, r2, r3, r4]

    for root in possible_roots:
        try:
            decrypted_message = root.to_bytes((root.bit_length() + 7) // 8, 'big').decode()
            return decrypted_message  # Return the first valid string
        except:
            continue

    return "Decryption failed: Unable to convert decrypted data to a valid string."

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

# --- RSA Functions ---
def rsa_keygen(bit_size=512):
    p = randprime(2 ** (bit_size - 1), 2 ** bit_size)
    q = randprime(2 ** (bit_size - 1), 2 ** bit_size)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = 65537  # Common choice for e
    d = modinv(e, phi_n)
    return (e, n, d)

def rsa_sign(d, n, message):
    h = int(sha256(message.encode()).hexdigest(), 16)
    return pow(h, d, n)

def rsa_verify(e, n, message, signature):
    h = int(sha256(message.encode()).hexdigest(), 16)
    h_v = pow(signature, e, n)
    return h == h_v

def create_digest(message):
    return sha256(message.encode()).hexdigest()

# --- Menu Driven System ---
class SecureSystem:
    def __init__(self):
        self.nurse_rabin_keys = rabin_keygen()
        self.nurse_rsa_keys = rsa_keygen()
        self.doctor_rabin_keys = rabin_keygen()
        self.doctor_rsa_keys = rsa_keygen()
        self.encrypted_data = None
        self.signature = None
        self.prescription = None
        self.logs = []  # To store logs

    def nurse(self):
        print("\nNurse's Role:")
        patient_details = input("Enter patient details: ")

        # Encrypt with Rabin
        _, _, n = self.doctor_rabin_keys
        self.encrypted_data = rabin_encrypt(n, patient_details)
        log_entry = f"Encrypted Data: {self.encrypted_data}"
        self.logs.append(log_entry)  # Log the encrypted data
        print(log_entry)

        # Sign with RSA
        e, n, d = self.nurse_rsa_keys
        self.signature = rsa_sign(d, n, str(self.encrypted_data))
        log_entry = f"Digital Signature: {self.signature}"
        self.logs.append(log_entry)  # Log the digital signature
        print(log_entry)

    def doctor(self):
        print("\nDoctor's Role:")

        # Verify Signature
        e, n, _ = self.nurse_rsa_keys
        valid = rsa_verify(e, n, str(self.encrypted_data), self.signature)

        if not valid:
            print("Signature verification failed.")
            return

        print("Signature verified successfully.")

        # Decrypt with Rabin
        p, q, n = self.doctor_rabin_keys
        decrypted_data = rabin_decrypt(p, q, n, self.encrypted_data)
        print(f"Decrypted Data (Patient Details): {decrypted_data}")

        # Write prescription
        self.prescription = input("Write a prescription: ")

    def technician(self):
        print("\nTechnician's Role:")

        # Create Message Digest using SHA-256
        if self.prescription:
            digest = create_digest(self.prescription)
            print(f"Message Digest (SHA-256): {digest}")
        else:
            print("No prescription to create a digest from.")

    def view_logs(self):
        print("\nLogs:")
        if not self.logs:
            print("No logs available.")
        else:
            for log in self.logs:
                print(log)

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
                # View logs
                self.view_logs()
            elif choice == '5':
                break
            else:
                print("Invalid option, try again.")


# Instantiate the system and run
system = SecureSystem()
system.run()
