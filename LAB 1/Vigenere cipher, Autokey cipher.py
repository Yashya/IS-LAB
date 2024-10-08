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


# Testing the ciphers
plaintext = "thehouseisbeingsoldtonight".lower()

# Vigenere Cipher with key "dollars"
vigenere_key = "dollars"
vigenere_encrypted = vigenere_encrypt(plaintext, vigenere_key)
vigenere_decrypted = vigenere_decrypt(vigenere_encrypted, vigenere_key)
print(f"Vigenere Cipher:\nEncrypted: {vigenere_encrypted}\nDecrypted: {vigenere_decrypted}")

# Autokey Cipher with key = 7
autokey_key = 7
autokey_encrypted = autokey_encrypt(plaintext, autokey_key)
autokey_decrypted = autokey_decrypt(autokey_encrypted, autokey_key)
print(f"\nAutokey Cipher:\nEncrypted: {autokey_encrypted}\nDecrypted: {autokey_decrypted}")
