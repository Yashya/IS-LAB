def char_to_num(char):
    return ord(char) - ord('a')


def num_to_char(num):
    return chr(num + ord('a'))


# Vigenère Cipher
def vigenere_encrypt(plaintext, key):
    ciphertext = ''
    key = key.lower()
    key_length = len(key)
    for i, char in enumerate(plaintext):
        if char.isalpha():
            p_num = char_to_num(char)
            k_num = char_to_num(key[i % key_length])
            encrypted_num = (p_num + k_num) % 26
            ciphertext += num_to_char(encrypted_num)
    return ciphertext


def vigenere_decrypt(ciphertext, key):
    plaintext = ''
    key = key.lower()
    key_length = len(key)
    for i, char in enumerate(ciphertext):
        if char.isalpha():
            c_num = char_to_num(char)
            k_num = char_to_num(key[i % key_length])
            decrypted_num = (c_num - k_num) % 26
            plaintext += num_to_char(decrypted_num)
    return plaintext


# Autokey Cipher
def autokey_encrypt(plaintext, key):
    ciphertext = ''
    key_stream = [key]  # Start with the key, then use plaintext letters as key
    for i, char in enumerate(plaintext):
        if i < len(key_stream):  # Use the key or autokey part
            k_num = key_stream[i]
        else:
            k_num = char_to_num(plaintext[i - len(key_stream)])
            key_stream.append(k_num)

        p_num = char_to_num(char)
        encrypted_num = (p_num + k_num) % 26
        ciphertext += num_to_char(encrypted_num)
    return ciphertext


def autokey_decrypt(ciphertext, key):
    plaintext = ''
    key_stream = [key]  # Start with the key, then use decrypted text as key
    for i, char in enumerate(ciphertext):
        if i < len(key_stream):  # Use the key or autokey part
            k_num = key_stream[i]
        else:
            k_num = char_to_num(plaintext[i - len(key_stream)])
            key_stream.append(k_num)

        c_num = char_to_num(char)
        decrypted_num = (c_num - k_num) % 26
        plaintext += num_to_char(decrypted_num)
    return plaintext


# Menu-driven program
def main():
    while True:
        print("\n=== Cipher Menu ===")
        print("1. Vigenere Cipher")
        print("2. Autokey Cipher")
        print("3. Exit")
        choice = input("Choose an option (1-3): ")

        if choice == '1':
            # Vigenère Cipher
            plaintext = input("Enter the message (no spaces between words): ").lower()
            key = input("Enter the key (string): ").lower()
            encrypted = vigenere_encrypt(plaintext, key)
            print(f"Encrypted Message: {encrypted}")
            decrypted = vigenere_decrypt(encrypted, key)
            print(f"Decrypted Message: {decrypted}")

        elif choice == '2':
            # Autokey Cipher
            plaintext = input("Enter the message (no spaces between words): ").lower()
            key = int(input("Enter the key (numeric): "))
            encrypted = autokey_encrypt(plaintext, key)
            print(f"Encrypted Message: {encrypted}")
            decrypted = autokey_decrypt(encrypted, key)
            print(f"Decrypted Message: {decrypted}")

        elif choice == '3':
            # Exit
            print("Exiting the program.")
            break

        else:
            print("Invalid choice. Please select a valid option.")


if __name__ == "__main__":
    main()
