import random
import logging
from Crypto.Util.number import getPrime, inverse, GCD
from datetime import datetime, timedelta

# Configure logging for auditing and compliance
logging.basicConfig(filename="key_management.log", level=logging.INFO, format='%(asctime)s %(message)s')

# Centralized Key Management Service for Rabin Cryptosystem
class CentralizedKeyManagementService:
    def __init__(self, key_size=1024):
        self.key_size = key_size  # Configurable key size
        self.hospitals = {}  # Store public and private keys for hospitals
        self.key_expiration = timedelta(days=365)  # Key renewal interval (12 months)

    def generate_rabin_keypair(self):
        # Generate Rabin cryptosystem keys
        while True:
            p = getPrime(self.key_size // 2)
            q = getPrime(self.key_size // 2)
            if p % 4 == 3 and q % 4 == 3:
                break
        n = p * q
        return (n, (p, q))  # Public key n, Private key (p, q)

    def register_hospital(self, hospital_id):
        # Generate keys for a new hospital
        public_key, private_key = self.generate_rabin_keypair()
        self.hospitals[hospital_id] = {
            "public_key": public_key,
            "private_key": private_key,
            "created_at": datetime.now(),
            "expires_at": datetime.now() + self.key_expiration,
            "revoked": False
        }
        logging.info(f"Generated keys for {hospital_id}. Public Key: {public_key}")
        print(f"Keys generated and stored for {hospital_id}.")

    def distribute_keys(self, hospital_id):
        # Provide keys to the requesting hospital
        if hospital_id in self.hospitals and not self.hospitals[hospital_id]['revoked']:
            logging.info(f"Distributed keys to {hospital_id}.")
            return self.hospitals[hospital_id]["public_key"], self.hospitals[hospital_id]["private_key"]
        else:
            logging.warning(f"Key distribution failed for {hospital_id}. Revoked or Non-existent.")
            return None

    def revoke_keys(self, hospital_id):
        # Revoke keys for a specific hospital
        if hospital_id in self.hospitals:
            self.hospitals[hospital_id]["revoked"] = True
            logging.info(f"Revoked keys for {hospital_id}.")
            print(f"Keys revoked for {hospital_id}.")
        else:
            logging.warning(f"Tried to revoke keys for non-existent {hospital_id}.")
            print(f"Hospital {hospital_id} does not exist.")

    def renew_keys(self):
        # Renew keys for all hospitals whose keys have expired
        for hospital_id, info in self.hospitals.items():
            if datetime.now() > info["expires_at"]:
                public_key, private_key = self.generate_rabin_keypair()
                self.hospitals[hospital_id] = {
                    "public_key": public_key,
                    "private_key": private_key,
                    "created_at": datetime.now(),
                    "expires_at": datetime.now() + self.key_expiration,
                    "revoked": False
                }
                logging.info(f"Renewed keys for {hospital_id}. New Public Key: {public_key}")
                print(f"Keys renewed for {hospital_id}.")

    def audit_logs(self):
        # Display log file content for auditing
        print("\n--- Audit Logs ---")
        with open("key_management.log", "r") as log_file:
            for line in log_file:
                print(line.strip())

# Trade-off Analysis: Rabin vs RSA
def tradeoff_analysis():
    print("\n--- Trade-off Analysis: Rabin vs RSA ---")
    print("1. Rabin is based on the difficulty of factoring n = p*q, similar to RSA.")
    print("2. The Rabin cryptosystem is as secure as RSA but requires p and q to be congruent to 3 mod 4.")
    print("3. Rabin produces four possible plaintexts during decryption, making it slightly complex.")
    print("4. RSA is more widely used and understood, with robust implementations.")
    print("5. Both offer similar performance for encryption/decryption, but RSA has more padding schemes.")

# Command-line Interface for Key Management
def main():
    # Initialize the key management service
    key_management_service = CentralizedKeyManagementService()

    while True:
        print("\n--- Centralized Key Management Service ---")
        print("1. Register New Hospital/Clinic")
        print("2. Distribute Keys to Hospital/Clinic")
        print("3. Revoke Keys for Hospital/Clinic")
        print("4. Renew All Keys")
        print("5. Audit Logs")
        print("6. Trade-off Analysis: Rabin vs RSA")
        print("7. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            hospital_id = input("Enter Hospital/Clinic ID: ")
            key_management_service.register_hospital(hospital_id)

        elif choice == "2":
            hospital_id = input("Enter Hospital/Clinic ID: ")
            keys = key_management_service.distribute_keys(hospital_id)
            if keys:
                print(f"Public Key: {keys[0]}")
                print(f"Private Key: {keys[1]}")

        elif choice == "3":
            hospital_id = input("Enter Hospital/Clinic ID: ")
            key_management_service.revoke_keys(hospital_id)

        elif choice == "4":
            print("Renewing keys for all hospitals and clinics...")
            key_management_service.renew_keys()

        elif choice == "5":
            key_management_service.audit_logs()

        elif choice == "6":
            tradeoff_analysis()

        elif choice == "7":
            print("Exiting the program.")
            break

        else:
            print("Invalid choice! Please try again.")

# Run the command-line interface
if __name__ == "__main__":
    main()
