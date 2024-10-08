import os
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# Function to generate ElGamal keys using secp256r1 curve
def generate_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


# Function to encrypt a message using the recipient's public key
def elgamal_encrypt(public_key, message):
    # Generate a random ephemeral key
    ephemeral_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ephemeral_public_key = ephemeral_private_key.public_key()

    # Generate shared secret
    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), public_key)

    # Derive a key from the shared secret
    derived_key = hashes.Hash(hashes.SHA256(), backend=default_backend())
    derived_key.update(shared_secret)
    key = derived_key.finalize()

    # Encrypt the message using AES-GCM
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()

    return ephemeral_public_key, ciphertext, encryptor.tag, nonce


# Function to decrypt the ciphertext using the private key
def elgamal_decrypt(private_key, ephemeral_public_key, ciphertext, tag, nonce):
    # Generate shared secret
    shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public_key)

    # Derive the same key used for encryption
    derived_key = hashes.Hash(hashes.SHA256(), backend=default_backend())
    derived_key.update(shared_secret)
    key = derived_key.finalize()

    # Decrypt the message using AES-GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()

    return decrypted_message


# Function to measure performance of encryption and decryption
def measure_performance(message):
    # Generate keys
    private_key, public_key = generate_keys()

    # Measure encryption time
    start_time = time.time()
    ephemeral_public_key, ciphertext, tag, nonce = elgamal_encrypt(public_key, message)
    encryption_time = time.time() - start_time

    # Measure decryption time
    start_time = time.time()
    decrypted_message = elgamal_decrypt(private_key, ephemeral_public_key, ciphertext, tag, nonce)
    decryption_time = time.time() - start_time

    # Verify the decrypted message
    assert decrypted_message == message, "Decryption failed: Messages do not match."

    # Print results
    print(f"Message Size: {len(message)} bytes")
    print(f"Ciphertext (encrypted message): {ciphertext.hex()}")  # Print the encrypted message in hex
    print(f"Encryption Time: {encryption_time:.6f}s | Decryption Time: {decryption_time:.6f}s")


def main():
    # Take user input for the message
    message = input("Enter the message to encrypt: ").encode()  # Encode the message to bytes
    measure_performance(message)


if __name__ == "__main__":
    main()
