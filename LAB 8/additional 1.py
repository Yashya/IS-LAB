import gnupg
import os

# Initialize GnuPG
gpg = gnupg.GPG()

# Function to generate a key pair
def generate_key():
    input_data = gpg.gen_key_input(name_email='your-email@example.com', passphrase='your-passphrase')
    key = gpg.gen_key(input_data)
    print(f"Key generated: {key}")
    return key

# Function to export the public key
def export_public_key():
    public_key = gpg.export_keys('your-email@example.com')
    with open('public_key.asc', 'w') as f:
        f.write(public_key)
    print("Public key exported to public_key.asc")

# Function to encrypt data
def encrypt_file(file_path, recipient_email):
    with open(file_path, 'rb') as f:
        status = gpg.encrypt_file(f, recipients=[recipient_email], output=f"{file_path}.gpg")
    print("Encryption status:", status.ok)
    if status.ok:
        print(f"Encrypted file created: {file_path}.gpg")

# Function to sign the data
def sign_file(file_path):
    with open(file_path, 'rb') as f:
        status = gpg.sign_file(f, passphrase='your-passphrase', output=f"{file_path}.sig")
    print("Signing status:", status.ok)
    if status.ok:
        print(f"Signature created: {file_path}.sig")

# Function to verify the signature
def verify_signature(sig_file, original_file):
    with open(sig_file, 'rb') as f:
        verified = gpg.verify_file(f, original_file)
    print("Verification status:", verified)
    return verified

# Function to decrypt data
def decrypt_file(encrypted_file, passphrase):
    with open(encrypted_file, 'rb') as f:
        status = gpg.decrypt_file(f, passphrase=passphrase, output=f"decrypted_{encrypted_file[:-4]}.txt")
    print("Decryption status:", status.ok)
    if status.ok:
        print(f"Decrypted file created: decrypted_{encrypted_file[:-4]}.txt")

# Main function to demonstrate the functionalities
def main():
    # Generate a key (if not already created)
    # generate_key()
    # export_public_key()

    # Encrypt and sign the data
    original_file = "secret.txt"
    with open(original_file, 'w') as f:
        f.write("This is a secret message.")

    recipient_email = 'recipient-email@example.com'  # Replace with actual recipient's email
    encrypt_file(original_file, recipient_email)
    sign_file(original_file)

    # Verify the signature
    verify_signature(f"{original_file}.sig", original_file)

    # Decrypt the data
    decrypt_file(f"{original_file}.gpg", 'your-passphrase')

if __name__ == "__main__":
    main()
