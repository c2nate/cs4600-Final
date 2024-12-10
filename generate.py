from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_rsa_keys():
    """
    Generate an RSA public-private key pair and save them to PEM files.
    """
    # Generate RSA private key with a public exponent of 65537 and key size of 2048 bits.
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Extract the public key from the generated private key.
    public_key = private_key.public_key()

    # Save the private key to a file in PEM format.
    with open("private_key.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,  # Format: PEM (Privacy-Enhanced Mail)
                format=serialization.PrivateFormat.PKCS8,  # Private key standard
                encryption_algorithm=serialization.NoEncryption()  # No encryption on the file
            )
        )

    # Save the public key to a file in PEM format.
    with open("public_key.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,  # Format: PEM
                format=serialization.PublicFormat.SubjectPublicKeyInfo  # Public key standard
            )
        )

    print("RSA key pair generated and saved to 'private_key.pem' and 'public_key.pem'.")

# Main function to generate keys when this script is run directly.
if __name__ == "__main__":
    generate_rsa_keys()
