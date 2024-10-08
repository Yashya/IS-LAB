from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
import time
import binascii


def des_encrypt(plaintext, key):
    des = DES.new(key.encode('utf-8'), DES.MODE_CBC)
    padded_plaintext = pad(plaintext.encode('utf-8'), DES.block_size)
    ciphertext = des.encrypt(padded_plaintext)
    return des.iv.hex(), binascii.hexlify(ciphertext).decode('utf-8')


def des_decrypt(ciphertext, key, iv):
    des = DES.new(key.encode('utf-8'), DES.MODE_CBC, bytes.fromhex(iv))
    decrypted_padded_plaintext = des.decrypt(binascii.unhexlify(ciphertext))
    decrypted_plaintext = unpad(decrypted_padded_plaintext, DES.block_size).decode('utf-8')
    return decrypted_plaintext


def aes_encrypt(plaintext, key):
    aes = AES.new(key.encode('utf-8'), AES.MODE_CBC)
    padded_plaintext = pad(plaintext.encode('utf-8'), AES.block_size)
    ciphertext = aes.encrypt(padded_plaintext)
    return aes.iv.hex(), binascii.hexlify(ciphertext).decode('utf-8')


def aes_decrypt(ciphertext, key, iv):
    aes = AES.new(key.encode('utf-8'), AES.MODE_CBC, bytes.fromhex(iv))
    decrypted_padded_plaintext = aes.decrypt(binascii.unhexlify(ciphertext))
    decrypted_plaintext = unpad(decrypted_padded_plaintext, AES.block_size).decode('utf-8')
    return decrypted_plaintext


def main():
    # Take user input for plaintext and keys
    plaintext = input("Enter the plaintext message to encrypt: ").strip()

    # DES key input
    des_key = input("Enter a 8-byte key for DES: ").strip()
    if len(des_key) != 8:
        print("Error: DES key must be exactly 8 characters long.")
        return

    # AES key input
    aes_key = input("Enter a 32-byte key for AES-256: ").strip()
    if len(aes_key) != 32:
        print("Error: AES-256 key must be exactly 32 characters long.")
        return

    # Measure DES encryption time
    start_time = time.time()
    iv, des_ciphertext = des_encrypt(plaintext, des_key)
    des_encrypt_time = time.time() - start_time

    # Measure DES decryption time
    start_time = time.time()
    des_decrypted = des_decrypt(des_ciphertext, des_key, iv)
    des_decrypt_time = time.time() - start_time

    # Measure AES encryption time
    start_time = time.time()
    iv, aes_ciphertext = aes_encrypt(plaintext, aes_key)
    aes_encrypt_time = time.time() - start_time

    # Measure AES decryption time
    start_time = time.time()
    aes_decrypted = aes_decrypt(aes_ciphertext, aes_key, iv)
    aes_decrypt_time = time.time() - start_time

    # Report findings
    print("=== Timing Results ===")
    print(f"DES Encryption Time: {des_encrypt_time:.6f} seconds")
    print(f"DES Decryption Time: {des_decrypt_time:.6f} seconds")
    print(f"AES-256 Encryption Time: {aes_encrypt_time:.6f} seconds")
    print(f"AES-256 Decryption Time: {aes_decrypt_time:.6f} seconds")

    # Verify that decrypted texts match original message
    print(f"DES Decryption Correct: {des_decrypted == plaintext}")
    print(f"AES Decryption Correct: {aes_decrypted == plaintext}")


if __name__ == "__main__":
    main()
