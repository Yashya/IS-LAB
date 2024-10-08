import os
import logging
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime
from cryptography.hazmat.backends import default_backend  # Import this line

# Configure Logging
logging.basicConfig(filename='key_management.log', level=logging.INFO)


class KMS:
    def __init__(self):
        self.keys = {}
        self.key_size = 1024  # Configurable key size
        self.renewal_period = 365  # in days

    def generate_key_pair(self, name):
        # Generate a private key and public key pair using RSA for simplicity
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()  # Correctly use the backend here
        )
        public_key = private_key.public_key()

        # Serialize keys with the required encryption algorithm
        private_key_serialized = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()  # No encryption for simplicity
        )
        public_key_serialized = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        self.keys[name] = {
            'private_key': private_key_serialized,
            'public_key': public_key_serialized,
            'last_renewal': datetime.now()
        }

        logging.info(f"{datetime.now()}: Generated keys for {name}.")
        return public_key_serialized, private_key_serialized

    def distribute_keys(self, name):
        if name in self.keys:
            logging.info(f"{datetime.now()}: Distributing keys for {name}.")
            return self.keys[name]['public_key'], self.keys[name]['private_key']
        else:
            logging.warning(f"{datetime.now()}: Key request for non-existing entity {name}.")
            return None, None

    def revoke_key(self, name):
        if name in self.keys:
            del self.keys[name]
            logging.info(f"{datetime.now()}: Revoked keys for {name}.")
        else:
            logging.warning(f"{datetime.now()}: Revocation attempted for non-existing entity {name}.")

    def renew_keys(self):
        for name, data in self.keys.items():
            # Check if keys need to be renewed
            if (datetime.now() - data['last_renewal']).days >= self.renewal_period:
                self.generate_key_pair(name)
                logging.info(f"{datetime.now()}: Renewed keys for {name}.")

    def audit_logs(self):
        with open('key_management.log', 'r') as file:
            logs = file.readlines()
        return logs


# Example usage
def main():
    kms = KMS()

    while True:
        print("\nKey Management System")
        print("1. Generate Key Pair")
        print("2. Distribute Keys")
        print("3. Revoke Key")
        print("4. Renew Keys")
        print("5. Audit Logs")
        print("6. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            name = input("Enter name for the new entity (hospital/clinic): ")
            kms.generate_key_pair(name)

        elif choice == '2':
            name = input("Enter name to distribute keys: ")
            public_key, private_key = kms.distribute_keys(name)
            if public_key:
                print(f"Public Key: {public_key.decode()}")
                print(f"Private Key: {private_key.decode()}")

        elif choice == '3':
            name = input("Enter name to revoke keys: ")
            kms.revoke_key(name)

        elif choice == '4':
            kms.renew_keys()
            print("Renewed keys for entities needing renewal.")

        elif choice == '5':
            logs = kms.audit_logs()
            for log in logs:
                print(log.strip())

        elif choice == '6':
            print("Exiting...")
            break

        else:
            print("Invalid choice, please try again.")


if __name__ == "__main__":
    main()
