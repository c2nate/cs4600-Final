import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import padding

def decrypt_message(private_key_path):
    # Load the receiver's private key
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    # Read transmitted data from JSON file
    with open("Transmitted_Data.json", "r") as f:
        transmitted_data = json.load(f)

    encrypted_message = bytes.fromhex(transmitted_data["encrypted_message"])
    encrypted_aes_key = bytes.fromhex(transmitted_data["encrypted_aes_key"])
    iv = bytes.fromhex(transmitted_data["iv"])
    mac = bytes.fromhex(transmitted_data["mac"])

    # Decrypt the AES key using the receiver's private key
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Verify the MAC
    h = hmac.HMAC(aes_key, hashes.SHA256())
    h.update(encrypted_message)
    try:
        h.verify(mac)
        print("MAC verification successful.")
    except Exception as e:
        print("MAC verification failed:", str(e))
        return

    # Decrypt the message using AES in CBC mode
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_message = decryptor.update(encrypted_message) + decryptor.finalize()

    # Remove padding
    padding_length = padded_message[-1]
    message = padded_message[:-padding_length]

    print("Decrypted Message:", message.decode())

# Main execution
if __name__ == "__main__":
    decrypt_message("private_key.pem")
