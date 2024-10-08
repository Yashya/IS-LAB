from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import time
import binascii


def triple_des_encrypt(plaintext, key):
    # Create a DES3 cipher object
    cipher = DES3.new(key.encode('utf-8'), DES3.MODE_CBC)

    # Pad the plaintext to make it a multiple of 8 bytes
    padded_plaintext = pad(plaintext.encode('utf-8'), DES3.block_size)

    # Encrypt the plaintext
    ciphertext = cipher.encrypt(padded_plaintext)

    return cipher.iv.hex(), binascii.hexlify(ciphertext).decode('utf-8')


def triple_des_decrypt(ciphertext, key, iv):
    # Create a DES3 cipher object with the same key and IV
    cipher = DES3.new(key.encode('utf-8'), DES3.MODE_CBC, bytes.fromhex(iv))

    # Decrypt the ciphertext
    decrypted_padded_plaintext = cipher.decrypt(binascii.unhexlify(ciphertext))

    # Unpad the decrypted plaintext
    decrypted_plaintext = unpad(decrypted_padded_plaintext, DES3.block_size).decode('utf-8')

    return decrypted_plaintext


def main():
    # Input plaintext and key
    plaintext = input("Enter the plaintext message: ")

    # Prompt the user for a valid 24-byte key for Triple DES
    while True:
        key = input("Enter a 24-byte key for Triple DES: ")
        if len(key) == 24:
            break
        else:
            print("Invalid key length. Please enter exactly 24 characters.")

    # Measure encryption time
    start_time = time.time()
    iv, ciphertext = triple_des_encrypt(plaintext, key)
    encrypt_time = time.time() - start_time

    # Measure decryption time
    start_time = time.time()
    decrypted_message = triple_des_decrypt(ciphertext, key, iv)
    decrypt_time = time.time() - start_time

    # Report findings
    print("\n=== Timing Results ===")
    print(f"Triple DES Encryption Time: {encrypt_time:.6f} seconds")
    print(f"Triple DES Decryption Time: {decrypt_time:.6f} seconds")
    print(f"Ciphertext: {ciphertext}")
    print(f"Decrypted Message: {decrypted_message}")
    print(f"Decryption Correct: {decrypted_message == plaintext}")


if __name__ == "__main__":
    main()
