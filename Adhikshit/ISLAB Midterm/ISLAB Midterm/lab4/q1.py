import os
from cryptography.hazmat.primitives.asymmetric import rsa, dh, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import base64
# Key management system
class KeyManagementSystem:
    def __init__(self):
        self.keys = {}

    def generate_rsa_key(self, name):
        """Generate and save RSA key pair."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        public_key = private_key.public_key()
        self.keys[name] = {'private_key': private_key, 'public_key': public_key}
        self._save_key(name, private_key, 'private')
        self._save_key(name, public_key, 'public')

    def _save_key(self, name, key, key_type):
        """Save key to file."""
        key_bytes = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ) if key_type == 'private' else key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(f'{name}_{key_type}_key.pem', 'wb') as f:
            f.write(key_bytes)

    def load_keys(self, name):
        """Load private and public keys from file."""
        with open(f'{name}_private_key.pem', 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        with open(f'{name}_public_key.pem', 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
        self.keys[name] = {'private_key': private_key, 'public_key': public_key}

    def revoke_key(self, name):
        """Revoke and delete keys."""
        if name in self.keys:
            del self.keys[name]
            os.remove(f'{name}_private_key.pem')
            os.remove(f'{name}_public_key.pem')

# Diffie-Hellman key exchange
def diffie_hellman_key_exchange():
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    private_key_A, private_key_B = parameters.generate_private_key(), parameters.generate_private_key()
    shared_key_A = private_key_A.exchange(private_key_B.public_key())
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake', backend=default_backend()).derive(shared_key_A)

# RSA Encryption/Decryption
def rsa_encrypt(public_key, message):
    return base64.b64encode(public_key.encrypt(message, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)))

def rsa_decrypt(private_key, ciphertext):
    return private_key.decrypt(base64.b64decode(ciphertext), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

# Example usage
def main():
    kms = KeyManagementSystem()
    kms.generate_rsa_key("System_A")
    dh_key = diffie_hellman_key_exchange()
    print("Shared DH key:", base64.b64encode(dh_key).decode())

    public_key_A = kms.keys["System_A"]["public_key"]
    private_key_A = kms.keys["System_A"]["private_key"]

    encrypted_message = rsa_encrypt(public_key_A, b"Important financial report")
    print("Encrypted:", encrypted_message)

    decrypted_message = rsa_decrypt(private_key_A, encrypted_message)
    print("Decrypted:", decrypted_message.decode())

    kms.revoke_key("System_A")
if __name__ == "__main__":
    main()