import os
import time
import random
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


# Subsystem Class
class Subsystem:
    def __init__(self, name):
        self.name = name
        self.private_key = self.generate_rsa_keys()
        self.shared_keys = {}

    def generate_rsa_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        return private_key

    def get_public_key(self):
        return self.private_key.public_key()

    def encrypt_message(self, message, recipient_public_key):
        encrypted_message = recipient_public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_message

    def decrypt_message(self, encrypted_message):
        decrypted_message = self.private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_message.decode()

    def generate_dh_key_pair(self):
        p = 23  # a prime number
        g = 5  # a primitive root modulo p
        self.private_dh_key = random.randint(1, p - 1)  # private key
        self.public_dh_key = pow(g, self.private_dh_key, p)  # public key
        return p, g, self.public_dh_key

    def compute_shared_key(self, recipient_public_dh_key, p):
        shared_key = pow(recipient_public_dh_key, self.private_dh_key, p)
        return shared_key


# Key Management System
class KeyManagementSystem:
    def __init__(self):
        self.subsystems = {}

    def register_subsystem(self, subsystem):
        self.subsystems[subsystem.name] = subsystem

    def get_subsystem(self, name):
        return self.subsystems.get(name)

    def revoke_key(self, subsystem_name):
        if subsystem_name in self.subsystems:
            del self.subsystems[subsystem_name]
            print(f"{subsystem_name} revoked successfully.")


def main():
    kms = KeyManagementSystem()

    # Create subsystems
    finance_system = Subsystem("Finance System")
    hr_system = Subsystem("HR System")
    supply_chain_system = Subsystem("Supply Chain Management")

    # Register subsystems
    kms.register_subsystem(finance_system)
    kms.register_subsystem(hr_system)
    kms.register_subsystem(supply_chain_system)

    # Simulating Secure Communication
    print("Establishing secure communication...\n")

    # Generating DH key pairs
    p, g, finance_dh_public = finance_system.generate_dh_key_pair()
    _, _, hr_dh_public = hr_system.generate_dh_key_pair()

    # Compute shared keys
    finance_shared_key = finance_system.compute_shared_key(hr_dh_public, p)
    hr_shared_key = hr_system.compute_shared_key(finance_dh_public, p)

    print("Shared Key Established:")
    print(f"Finance Shared Key: {finance_shared_key}")
    print(f"HR Shared Key: {hr_shared_key}\n")

    # Sending a secure message
    message = "Confidential Financial Report"
    encrypted_message = finance_system.encrypt_message(message, hr_system.get_public_key())

    print(f"Encrypted Message from Finance to HR: {encrypted_message}")

    # HR receives and decrypts the message
    decrypted_message = hr_system.decrypt_message(encrypted_message)
    print(f"Decrypted Message received by HR: {decrypted_message}\n")

    # Revoking a subsystem
    kms.revoke_key("Supply Chain Management")


if __name__ == "__main__":
    main()
