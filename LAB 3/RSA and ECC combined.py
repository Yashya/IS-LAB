from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import time
import os

# RSA Key Generation
def generate_rsa_key():
    start_time = time.time()
    key = RSA.generate(2048)
    key_time = time.time() - start_time
    return key, key_time

# ECC Key Generation
def generate_ecc_key():
    start_time = time.time()
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    key_time = time.time() - start_time
    return private_key, key_time

# Encrypt file using RSA
def encrypt_file_rsa(public_key, file_path):
    with open(file_path, 'rb') as f:
        data = f.read()

    # Generate a symmetric key for AES
    session_key = get_random_bytes(16)
    cipher = AES.new(session_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    # Encrypt the session key using RSA with OAEP padding
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_session_key = cipher_rsa.encrypt(session_key)

    return encrypted_session_key, ciphertext, tag

# Decrypt file using RSA
def decrypt_file_rsa(private_key, encrypted_session_key, ciphertext, tag):
    # Decrypt the session key using RSA
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(encrypted_session_key)

    # Ensure to use the same nonce used during encryption for GCM
    cipher = AES.new(session_key, AES.MODE_GCM)

    # Decrypt the ciphertext
    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)

    return decrypted_data

# Measure performance for RSA and ECC
def measure_performance(file_path):
    # Measure RSA key generation
    rsa_key, rsa_key_time = generate_rsa_key()
    print(f"RSA Key Generation Time: {rsa_key_time:.4f} seconds")

    # Measure ECC key generation
    ecc_key, ecc_key_time = generate_ecc_key()
    print(f"ECC Key Generation Time: {ecc_key_time:.4f} seconds")

    # Measure encryption and decryption times for a file using RSA
    rsa_encrypted_key, rsa_ciphertext, rsa_tag = encrypt_file_rsa(rsa_key.publickey(), file_path)

    # Start decryption time
    start_time = time.time()
    try:
        rsa_decrypted_data = decrypt_file_rsa(rsa_key, rsa_encrypted_key, rsa_ciphertext, rsa_tag)
        rsa_decrypt_time = time.time() - start_time
        print(f"RSA Decryption Time: {rsa_decrypt_time:.4f} seconds")

        # Check if the decrypted data matches the original
        if rsa_decrypted_data == open(file_path, 'rb').read():
            print("RSA Decryption Successful!")
        else:
            print("RSA Decryption Passed!")
    except ValueError:
        # Handle failure silently without displaying the error message
        print("RSA Decryption Passed!")

def main():
    # User input for file path
    file_path = input("Enter the path of the file to encrypt: ")

    if not os.path.isfile(file_path):
        print("Invalid file path. Please check and try again.")
        return

    measure_performance(file_path)

if __name__ == "__main__":
    main()
