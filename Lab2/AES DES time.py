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
    message = "Performance Testing of Encryption Algorithms"
    des_key = "ABCDEFGH"  # DES requires a key of exactly 8 bytes
    aes_key = "0123456789ABCDEF0123456789ABCDEF"  # 32 bytes for AES-256

    # Measure DES encryption time
    start_time = time.time()
    iv, des_ciphertext = des_encrypt(message, des_key)
    des_encrypt_time = time.time() - start_time

    # Measure DES decryption time
    start_time = time.time()
    des_decrypted = des_decrypt(des_ciphertext, des_key, iv)
    des_decrypt_time = time.time() - start_time

    # Measure AES encryption time
    start_time = time.time()
    iv, aes_ciphertext = aes_encrypt(message, aes_key)
    aes_encrypt_time = time.time() - start_time

    # Measure AES decryption time
    start_time = time.time()
    aes_decrypted = aes_decrypt(aes_ciphertext, aes_key, iv)
    aes_decrypt_time = time.time() - start_time

    # Report findings
    print("DES Encryption Time: {:.6f} seconds".format(des_encrypt_time))
    print("DES Decryption Time: {:.6f} seconds".format(des_decrypt_time))
    print("AES-256 Encryption Time: {:.6f} seconds".format(aes_encrypt_time))
    print("AES-256 Decryption Time: {:.6f} seconds".format(aes_decrypt_time))

    # Verify that decrypted texts match original message
    print(f"DES Decryption Correct: {des_decrypted == message}")
    print(f"AES Decryption Correct: {aes_decrypted == message}")

if __name__ == "__main__":
    main()
