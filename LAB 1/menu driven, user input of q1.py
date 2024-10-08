def char_to_num(char):
    return ord(char) - ord('a')

def num_to_char(num):
    return chr(num + ord('a'))

# Additive Cipher
def additive_encrypt(plaintext, key):
    ciphertext = ''
    for char in plaintext:
        if char.isalpha():
            num = char_to_num(char)
            encrypted_num = (num + key) % 26
            ciphertext += num_to_char(encrypted_num)
    return ciphertext

def additive_decrypt(ciphertext, key):
    plaintext = ''
    for char in ciphertext:
        if char.isalpha():
            num = char_to_num(char)
            decrypted_num = (num - key) % 26
            plaintext += num_to_char(decrypted_num)
    return plaintext

# Multiplicative Cipher
def multiplicative_encrypt(plaintext, key):
    ciphertext = ''
    for char in plaintext:
        if char.isalpha():
            num = char_to_num(char)
            encrypted_num = (num * key) % 26
            ciphertext += num_to_char(encrypted_num)
    return ciphertext

def multiplicative_decrypt(ciphertext, key):
    # Inverse of 15 modulo 26 is 7
    inverse_key = 7
    plaintext = ''
    for char in ciphertext:
        if char.isalpha():
            num = char_to_num(char)
            decrypted_num = (num * inverse_key) % 26
            plaintext += num_to_char(decrypted_num)
    return plaintext

# Affine Cipher
def affine_encrypt(plaintext, key1, key2):
    ciphertext = ''
    for char in plaintext:
        if char.isalpha():
            num = char_to_num(char)
            encrypted_num = (num * key1 + key2) % 26
            ciphertext += num_to_char(encrypted_num)
    return ciphertext

def affine_decrypt(ciphertext, key1, key2):
    # Inverse of 15 modulo 26 is 7
    inverse_key1 = 7
    plaintext = ''
    for char in ciphertext:
        if char.isalpha():
            num = char_to_num(char)
            decrypted_num = (inverse_key1 * (num - key2)) % 26
            plaintext += num_to_char(decrypted_num)
    return plaintext

# Menu-driven program
def main():
    while True:
        print("\n=== Cipher Menu ===")
        print("1. Additive Cipher")
        print("2. Multiplicative Cipher")
        print("3. Affine Cipher")
        print("4. Exit")
        choice = input("Choose an option (1-4): ")

        if choice == '1':
            # Additive Cipher
            plaintext = input("Enter the message (no spaces between words): ").lower()
            key = int(input("Enter the key (numeric): "))
            encrypted = additive_encrypt(plaintext, key)
            print(f"Encrypted Message: {encrypted}")
            decrypted = additive_decrypt(encrypted, key)
            print(f"Decrypted Message: {decrypted}")

        elif choice == '2':
            # Multiplicative Cipher
            plaintext = input("Enter the message (no spaces between words): ").lower()
            key = int(input("Enter the key (must have a multiplicative inverse mod 26): "))
            encrypted = multiplicative_encrypt(plaintext, key)
            print(f"Encrypted Message: {encrypted}")
            decrypted = multiplicative_decrypt(encrypted, key)
            print(f"Decrypted Message: {decrypted}")

        elif choice == '3':
            # Affine Cipher
            plaintext = input("Enter the message (no spaces between words): ").lower()
            key1 = int(input("Enter the multiplicative key (key1): "))
            key2 = int(input("Enter the additive key (key2): "))
            encrypted = affine_encrypt(plaintext, key1, key2)
            print(f"Encrypted Message: {encrypted}")
            decrypted = affine_decrypt(encrypted, key1, key2)
            print(f"Decrypted Message: {decrypted}")

        elif choice == '4':
            # Exit
            print("Exiting the program.")
            break

        else:
            print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    main()
