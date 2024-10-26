import hashlib
from phe import paillier
from collections import defaultdict

# 2a. Generate text corpus
documents = [
    "The wind howled through the empty streets on a cold evening.",
    "An orange cat sat silently under the oak tree, watching the world.",
    "Quantum computing may revolutionize cryptographic systems.",
    "Bright colors danced across the sky during the sunset.",
    "The spaceship drifted silently through the vast emptiness of space.",
    "Baking a cake requires precision and patience for the best results.",
    "The ancient ruins held secrets that no one had yet uncovered.",
    "Robots are becoming an essential part of modern manufacturing.",
    "A mysterious note was left on the doorstep in the dead of night.",
    "The evolution of technology is accelerating faster than ever before."
]

# 2b. Generate Paillier keypair (public and private keys) for homomorphic encryption
public_key, private_key = paillier.generate_paillier_keypair()


def word_to_hash(word):
    """Convert a word to a hash representation using SHA-256."""
    return hashlib.sha256(word.encode("utf-8")).hexdigest()


def encrypt_ids(doc_ids, pub_key):
    """Encrypt document IDs using Paillier encryption."""
    return [pub_key.encrypt(doc_id) for doc_id in doc_ids]


def decrypt_ids(encrypted_doc_ids, priv_key):
    """Decrypt encrypted document IDs using Paillier decryption."""
    return [priv_key.decrypt(enc_id) for enc_id in encrypted_doc_ids]


def build_inverted_index(docs):
    """Build an inverted index from the given documents."""
    index = defaultdict(list)
    for doc_id, doc in enumerate(docs):
        for word in doc.split():
            word_hash = word_to_hash(word.lower())
            index[word_hash].append(doc_id)
    return index


def encrypt_inverted_index(index, pub_key):
    """Encrypt the document IDs in the inverted index."""
    encrypted_index = {}
    for word_hash, doc_ids in index.items():
        encrypted_index[word_hash] = encrypt_ids(doc_ids, pub_key)
    return encrypted_index


def search(query, encrypted_index, priv_key, documents):
    """Search for documents that match the given query."""
    query_hash = word_to_hash(query.lower())

    # Debugging: Print the hashed query
    print(f"Hashed Query: {query_hash}")

    if query_hash in encrypted_index:
        encrypted_doc_ids = encrypted_index[query_hash]

        # Debugging: Print encrypted document IDs
        print(f"Encrypted Doc IDs: {encrypted_doc_ids}")

        doc_ids = decrypt_ids(encrypted_doc_ids, priv_key)

        # Debugging: Print decrypted document IDs
        print(f"Decrypted Doc IDs: {doc_ids}")

        return [documents[doc_id] for doc_id in doc_ids if doc_id < len(documents)]
    else:
        return []


if __name__ == "__main__":
    inverted_index = build_inverted_index(documents)
    encrypted_index = encrypt_inverted_index(inverted_index, public_key)

    while True:
        query = input("Enter search query (or type 'exit' to quit): ").strip()

        if query.lower() == 'exit':
            print("Exiting the search program.")
            break

        results = search(query, encrypted_index, private_key, documents)

        if results:
            print("Documents matching query:")
            for result in results:
                print(f"- {result}")
        else:
            print("No matching documents found.")
