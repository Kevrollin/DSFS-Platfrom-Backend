# app/stellar_utils/key_security.py

from stellar_sdk import Keypair
from cryptography.fernet import Fernet
import os
# You might need to install python-dotenv for local development: pip install python-dotenv
from dotenv import load_dotenv
load_dotenv() # Load environment variables from .env fil

# --- Encryption Key Management ---
# Get your encryption key securely from environment variables
# You need to generate a strong Fernet key and set it as an environment variable
# Example command to generate a key (run once): python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
# Store this key securely and provide it via an environment variable like STELLAR_SECRET_KEY_ENCRYPTION_KEY
ENCRYPTION_KEY = os.getenv("STELLAR_SECRET_KEY_ENCRYPTION_KEY")

if not ENCRYPTION_KEY:
    raise ValueError("STELLAR_SECRET_KEY_ENCRYPTION_KEY environment variable not set.")

cipher_suite = Fernet(ENCRYPTION_KEY)

def generate_stellar_keypair():
    """Generates a new Stellar keypair."""
    keypair = Keypair.random()
    return {
        "public_key": keypair.public_key,
        "secret_key": keypair.secret
    }

def encrypt_secret_key(secret_key: str) -> str:
    """Encrypts a Stellar secret key."""
    try:
        # Encode the string secret key to bytes, encrypt, and then decode to string for storage
        return cipher_suite.encrypt(secret_key.encode()).decode()
    except Exception as e:
        print(f"Error encrypting secret key: {e}")
        # Handle encryption errors appropriately (e.g., log, raise custom exception)
        raise

def decrypt_secret_key(encrypted_secret_key: str) -> str:
    """Decrypts a Stellar secret key."""
    if not encrypted_secret_key:
        return None # Handle cases where there's no key stored

    try:
        # Encode the string encrypted key to bytes, decrypt, and then decode to string
        return cipher_suite.decrypt(encrypted_secret_key.encode()).decode()
    except Exception as e:
        print(f"Error decrypting secret key: {e}")
        # Handle decryption errors (e.g., log, raise custom exception - could indicate tampered data)
        raise