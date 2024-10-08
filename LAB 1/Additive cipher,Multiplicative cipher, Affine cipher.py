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

# Testing the ciphers
plaintext = "iamlearninginformationsecurity"

# Additive Cipher with key=20
add_encrypted = additive_encrypt(plaintext, 20)
add_decrypted = additive_decrypt(add_encrypted, 20)
print(f"Additive Cipher:\nEncrypted: {add_encrypted}\nDecrypted: {add_decrypted}")

# Multiplicative Cipher with key=15
mult_encrypted = multiplicative_encrypt(plaintext, 15)
mult_decrypted = multiplicative_decrypt(mult_encrypted, 15)
print(f"\nMultiplicative Cipher:\nEncrypted: {mult_encrypted}\nDecrypted: {mult_decrypted}")

# Affine Cipher with keys (15, 20)
affine_encrypted = affine_encrypt(plaintext, 15, 20)
affine_decrypted = affine_decrypt(affine_encrypted, 15, 20)
print(f"\nAffine Cipher:\nEncrypted: {affine_encrypted}\nDecrypted: {affine_decrypted}")
