import os
import time
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Function to generate RSA keys
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Function to encrypt a message using RSA
def rsa_encrypt(public_key, message):
    # Encrypt the symmetric key using RSA
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

# Function to decrypt a ciphertext using RSA
def rsa_decrypt(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

# Function to generate ElGamal keys
def generate_elgamal_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# Function to encrypt a message using ElGamal
def elgamal_encrypt(public_key, message):
    ephemeral_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ephemeral_public_key = ephemeral_private_key.public_key()
    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), public_key)

    # Derive key from shared secret
    derived_key = hashes.Hash(hashes.SHA256(), backend=default_backend())
    derived_key.update(shared_secret)
    key = derived_key.finalize()

    # Encrypt the message using AES-GCM
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return ephemeral_public_key, ciphertext, encryptor.tag, nonce

# Function to decrypt a ciphertext using ElGamal
def elgamal_decrypt(private_key, ephemeral_public_key, ciphertext, tag, nonce):
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

# Function to generate random message of a given size
def generate_random_message(size_kb):
    return os.urandom(size_kb * 1024)  # size in bytes

# Function to measure performance
def measure_performance(message):
    # RSA
    print("RSA Encryption and Decryption:")
    rsa_private_key, rsa_public_key = generate_rsa_keys()

    # Encrypt the message using AES first
    symmetric_key = os.urandom(32)  # Generate a random 256-bit AES key
    aes_cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(b'\x00' * 16), backend=default_backend())
    encryptor = aes_cipher.encryptor()
    aes_ciphertext = encryptor.update(message) + encryptor.finalize()

    start_time = time.time()
    rsa_ciphertext = rsa_encrypt(rsa_public_key, symmetric_key)
    encryption_time_rsa = time.time() - start_time

    start_time = time.time()
    rsa_decrypted_key = rsa_decrypt(rsa_private_key, rsa_ciphertext)
    decryption_time_rsa = time.time() - start_time

    # Decrypt the AES ciphertext using the decrypted key
    aes_cipher_decryptor = Cipher(algorithms.AES(rsa_decrypted_key), modes.CFB(b'\x00' * 16), backend=default_backend()).decryptor()
    rsa_decrypted_message = aes_cipher_decryptor.update(aes_ciphertext) + aes_cipher_decryptor.finalize()

    assert rsa_decrypted_message == message, "RSA Decryption failed: Messages do not match."
    print(f"Encryption Time (RSA): {encryption_time_rsa:.6f}s | Decryption Time (RSA): {decryption_time_rsa:.6f}s")

    # ElGamal
    print("ElGamal Encryption and Decryption:")
    elgamal_private_key, elgamal_public_key = generate_elgamal_keys()

    start_time = time.time()
    ephemeral_public_key, elgamal_ciphertext, tag, nonce = elgamal_encrypt(elgamal_public_key, message)
    encryption_time_elgamal = time.time() - start_time

    start_time = time.time()
    elgamal_decrypted_message = elgamal_decrypt(elgamal_private_key, ephemeral_public_key, elgamal_ciphertext, tag, nonce)
    decryption_time_elgamal = time.time() - start_time

    assert elgamal_decrypted_message == message, "ElGamal Decryption failed: Messages do not match."
    print(f"Encryption Time (ElGamal): {encryption_time_elgamal:.6f}s | Decryption Time (ElGamal): {decryption_time_elgamal:.6f}s")

def main():
    # Measure performance for different message sizes
    for size in [1, 10]:  # sizes in KB
        message = generate_random_message(size)
        print(f"\nTesting with message size: {size} KB")
        measure_performance(message)

if __name__ == "__main__":
    main()
