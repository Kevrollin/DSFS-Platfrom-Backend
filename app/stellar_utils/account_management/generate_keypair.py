from stellar_sdk import Keypair

def generate_stellar_keypair():
    """Generates a new Stellar keypair."""
    keypair = Keypair.random()
    return {
        "public_key": keypair.public_key,
        "secret_key": keypair.secret
    }

# Example usage:
new_account_keys = generate_stellar_keypair()
print("Public Key:", new_account_keys["public_key"])
print("Secret Key:", new_account_keys["secret_key"]) # Keep this secret!