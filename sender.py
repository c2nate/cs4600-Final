import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import os

def encrypt_message(message, receiver_public_key_path):
    # Load the receiver's public key
    with open(receiver_public_key_path, "rb") as f:
        receiver_public_key = serialization.load_pem_public_key(f.read())

    # Generate a random 256-bit AES key
    aes_key = os.urandom(32)

    # Encrypt the message using AES in CBC mode
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Ensure message length is a multiple of block size by padding
    block_size = 16
    padding_length = block_size - (len(message) % block_size)
    padded_message = message + (chr(padding_length) * padding_length).encode()
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()

    # Encrypt the AES key with the receiver's RSA public key
    encrypted_aes_key = receiver_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Generate a MAC (HMAC-SHA256) for the encrypted message
    h = hmac.HMAC(aes_key, hashes.SHA256())
    h.update(encrypted_message)
    mac = h.finalize()

    # Save the transmitted data to a file in JSON format
    transmitted_data = {
        "encrypted_message": encrypted_message.hex(),
        "encrypted_aes_key": encrypted_aes_key.hex(),
        "iv": iv.hex(),
        "mac": mac.hex()
    }

    with open("Transmitted_Data.json", "w") as f:
        json.dump(transmitted_data, f)

    print("Message encrypted and saved to Transmitted_Data.json")

# Main execution
if __name__ == "__main__":
    # The plaintext message to send
    message = b"Hello, this is a secure message."

    # Call the encryption function
    encrypt_message(message, "public_key.pem")
