import os
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
        else:
            print(f"{subsystem_name} not found.")

    def list_subsystems(self):
        print("Registered Subsystems:")
        for name in self.subsystems.keys():
            print(f"- {name}")


def main():
    kms = KeyManagementSystem()

    # Menu Loop
    while True:
        print("\nSecureCorp Communication System")
        print("1. Register Subsystem")
        print("2. List Subsystems")
        print("3. Establish Secure Communication")
        print("4. Revoke Subsystem")
        print("5. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            name = input("Enter subsystem name (e.g., Finance System): ")
            subsystem = Subsystem(name)
            kms.register_subsystem(subsystem)
            print(f"Subsystem '{name}' registered successfully.")

        elif choice == '2':
            kms.list_subsystems()

        elif choice == '3':
            sender_name = input("Enter sender subsystem name: ")
            recipient_name = input("Enter recipient subsystem name: ")
            sender = kms.get_subsystem(sender_name)
            recipient = kms.get_subsystem(recipient_name)

            if sender and recipient:
                p, g, sender_dh_public = sender.generate_dh_key_pair()
                _, _, recipient_dh_public = recipient.generate_dh_key_pair()

                sender_shared_key = sender.compute_shared_key(recipient_dh_public, p)
                recipient_shared_key = recipient.compute_shared_key(sender_dh_public, p)

                print("Shared Key Established:")
                print(f"{sender_name} Shared Key: {sender_shared_key}")
                print(f"{recipient_name} Shared Key: {recipient_shared_key}")

                message = input("Enter message to send: ")
                encrypted_message = sender.encrypt_message(message, recipient.get_public_key())
                print(f"Encrypted Message: {encrypted_message}")

                decrypted_message = recipient.decrypt_message(encrypted_message)
                print(f"Decrypted Message received by {recipient_name}: {decrypted_message}")

            else:
                print("One or both subsystems not found.")

        elif choice == '4':
            name = input("Enter subsystem name to revoke: ")
            kms.revoke_key(name)

        elif choice == '5':
            print("Exiting...")
            break

        else:
            print("Invalid choice, please try again.")


if __name__ == "__main__":
    main()
