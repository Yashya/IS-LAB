from Crypto.Cipher import DES, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import binascii


# 1. DES Key Generation
def generate_des_key():
    key = get_random_bytes(8)  # DES requires a key of 8 bytes (64-bit key)
    return key


# 2. DES Encryption
def des_encrypt(message, key):
    cipher_des = DES.new(key, DES.MODE_ECB)  # DES with ECB mode
    padded_message = pad(message, DES.block_size)  # Pad the message to be a multiple of 8 bytes
    encrypted_message = cipher_des.encrypt(padded_message)  # Encrypt the message
    return encrypted_message


# 3. DES Decryption
def des_decrypt(ciphertext, key):
    cipher_des = DES.new(key, DES.MODE_ECB)  # DES with ECB mode
    decrypted_padded_message = cipher_des.decrypt(ciphertext)  # Decrypt the message
    decrypted_message = unpad(decrypted_padded_message, DES.block_size)  # Unpad the message
    return decrypted_message


# 4. AES Key Generation
def generate_aes_key():
    key = get_random_bytes(16)  # AES requires a key of 16 bytes (128-bit key)
    return key


# 5. AES Encryption
def aes_encrypt(message, key):
    cipher_aes = AES.new(key, AES.MODE_ECB)  # AES with ECB mode
    padded_message = pad(message, AES.block_size)  # Pad the message to be a multiple of 16 bytes
    encrypted_message = cipher_aes.encrypt(padded_message)  # Encrypt the message
    return encrypted_message


# 6. AES Decryption
def aes_decrypt(ciphertext, key):
    cipher_aes = AES.new(key, AES.MODE_ECB)  # AES with ECB mode
    decrypted_padded_message = cipher_aes.decrypt(ciphertext)  # Decrypt the message
    decrypted_message = unpad(decrypted_padded_message, AES.block_size)  # Unpad the message
    return decrypted_message


# Main function to demonstrate menu-driven operations
def main():
    # Generate DES and AES keys
    des_key = generate_des_key()
    aes_key = generate_aes_key()

    print("DES Key generated (Hexadecimal Format):", binascii.hexlify(des_key).decode())
    print("AES Key generated (Hexadecimal Format):", binascii.hexlify(aes_key).decode())

    while True:
        print("\n--- AES and DES Encryption/Decryption Menu ---")
        print("1. DES Encryption")
        print("2. DES Decryption")
        print("3. AES Encryption")
        print("4. AES Decryption")
        print("5. Exit")

        choice = int(input("Enter your choice: "))

        if choice == 1:
            # DES Encryption Operation
            message = input("Enter the message to be encrypted using DES: ").encode()
            encrypted_message = des_encrypt(message, des_key)
            print(f"\nOriginal Message: {message.decode()}")
            print(f"DES Encrypted Message (Hexadecimal): {binascii.hexlify(encrypted_message).decode()}")

        elif choice == 2:
            # DES Decryption Operation
            encrypted_message_hex = input("Enter the DES encrypted message in hexadecimal: ")
            try:
                encrypted_message = binascii.unhexlify(encrypted_message_hex)
                decrypted_message = des_decrypt(encrypted_message, des_key)
                print(f"\nDecrypted Message: {decrypted_message.decode()}")
            except (ValueError, TypeError):
                print("Invalid DES encrypted message format! Please enter a valid hexadecimal value.")

        elif choice == 3:
            # AES Encryption Operation
            message = input("Enter the message to be encrypted using AES: ").encode()
            encrypted_message = aes_encrypt(message, aes_key)
            print(f"\nOriginal Message: {message.decode()}")
            print(f"AES Encrypted Message (Hexadecimal): {binascii.hexlify(encrypted_message).decode()}")

        elif choice == 4:
            # AES Decryption Operation
            encrypted_message_hex = input("Enter the AES encrypted message in hexadecimal: ")
            try:
                encrypted_message = binascii.unhexlify(encrypted_message_hex)
                decrypted_message = aes_decrypt(encrypted_message, aes_key)
                print(f"\nDecrypted Message: {decrypted_message.decode()}")
            except (ValueError, TypeError):
                print("Invalid AES encrypted message format! Please enter a valid hexadecimal value.")

        elif choice == 5:
            print("Exiting the program.")
            break

        else:
            print("Invalid choice! Please select a valid option.")


# Run the program
if __name__ == "__main__":
    main()
