import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import os

def encrypt_message(message, receiver_public_key_path):
    """
    Encrypt a message using AES and secure the AES key with the receiver's RSA public key.
    Also, generate a MAC for message authentication.
    """

    # Step 1: Load the receiver's RSA public key from the PEM file.
    with open(receiver_public_key_path, "rb") as f:
        receiver_public_key = serialization.load_pem_public_key(f.read())

    # Step 2: Generate a random 256-bit AES key for message encryption.
    aes_key = os.urandom(32)  # 32 bytes = 256 bits

    # Step 3: Encrypt the message using AES in CBC mode with a random initialization vector (IV).
    iv = os.urandom(16)  # AES block size (128 bits = 16 bytes)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Ensure the message length is a multiple of the AES block size by adding PKCS#7 padding.
    block_size = 16  # AES block size in bytes
    padding_length = block_size - (len(message) % block_size)
    padded_message = message + (chr(padding_length) * padding_length).encode()  # Add padding
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()  # Encrypt the padded message

    # Step 4: Encrypt the AES key using the receiver's RSA public key.
    encrypted_aes_key = receiver_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Mask Generation Function
            algorithm=hashes.SHA256(),  # Hash algorithm for padding
            label=None
        )
    )

    # Step 5: Generate a MAC (Message Authentication Code) for the encrypted message.
    h = hmac.HMAC(aes_key, hashes.SHA256())  # Use the AES key as the MAC key
    h.update(encrypted_message)  # Hash the encrypted message
    mac = h.finalize()  # Generate the MAC

    # Step 6: Save the encrypted message, AES key, IV, and MAC to a JSON file.
    transmitted_data = {
        "encrypted_message": encrypted_message.hex(),  # Convert to hexadecimal for storage
        "encrypted_aes_key": encrypted_aes_key.hex(),
        "iv": iv.hex(),
        "mac": mac.hex()
    }

    with open("Transmitted_Data.json", "w") as f:
        json.dump(transmitted_data, f)

    print("Message encrypted and saved to 'Transmitted_Data.json'.")

# Main function to execute the sender's process.
if __name__ == "__main__":
    # Define the plaintext message to be sent.
    message = b"According to all known laws of aviation, there is no way a bee should be able to fly."

    # Call the encryption function with the message and receiver's public key file.
    encrypt_message(message, "public_key.pem")
