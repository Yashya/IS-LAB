from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives import serialization


# Generate RSA key pair
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    return private_key, public_key


# Sign a message using the private key
def sign_message(private_key, message):
    # Hash the message
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


# Verify the signature using the public key
def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Verification failed: {e}")
        return False


# Serialize and deserialize keys (optional)
def serialize_private_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


# Main flow
if __name__ == "__main__":
    # Step 1: Generate RSA key pair
    private_key, public_key = generate_rsa_keys()

    # Step 2: Input message from user
    message = input("Enter the message you want to sign: ").encode()

    # Step 3: Sign the message using the private key
    signature = sign_message(private_key, message)
    print(f"Signature: {signature.hex()}")

    # Step 4: Verify the signature using the public key
    is_valid = verify_signature(public_key, message, signature)

    if is_valid:
        print("Signature verification succeeded.")
    else:
        print("Signature verification failed.")
