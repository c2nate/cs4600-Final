import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import padding

def decrypt_message(private_key_path):
    """
    Decrypt a received message by first decrypting the AES key with the receiver's RSA private key,
    verifying the MAC for integrity, and then decrypting the message using AES.
    """

    # Step 1: Load the receiver's RSA private key from the PEM file.
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    # Step 2: Read the transmitted data from the JSON file.
    with open("Transmitted_Data.json", "r") as f:
        transmitted_data = json.load(f)

    # Extract encrypted components from the JSON file.
    encrypted_message = bytes.fromhex(transmitted_data["encrypted_message"])
    encrypted_aes_key = bytes.fromhex(transmitted_data["encrypted_aes_key"])
    iv = bytes.fromhex(transmitted_data["iv"])
    mac = bytes.fromhex(transmitted_data["mac"])

    # Step 3: Decrypt the AES key using the RSA private key.
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Mask Generation Function
            algorithm=hashes.SHA256(),  # Hash algorithm for padding
            label=None
        )
    )

    # Step 4: Verify the MAC to ensure message integrity.
    h = hmac.HMAC(aes_key, hashes.SHA256())  # Initialize HMAC with the decrypted AES key
    h.update(encrypted_message)  # Hash the encrypted message
    try:
        h.verify(mac)  # Verify the MAC
        print("MAC verification successful.")
    except Exception as e:
        print("MAC verification failed:", str(e))
        return

    # Step 5: Decrypt the message using AES in CBC mode with the decrypted AES key and IV.
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_message = decryptor.update(encrypted_message) + decryptor.finalize()  # Decrypt the message

    # Remove PKCS#7 padding to retrieve the original plaintext message.
    padding_length = padded_message[-1]  # The last byte indicates the padding length
    message = padded_message[:-padding_length]  # Remove the padding

    print("Decrypted Message:", message.decode())  # Output the original plaintext

# Main function to execute the receiver's process.
if __name__ == "__main__":
    # Call the decryption function with the receiver's private key file.
    decrypt_message("private_key.pem")
