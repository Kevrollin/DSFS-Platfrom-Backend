# Assuming 'transaction' is built from 2.3.4
from stellar_sdk import Keypair

def sign_transaction_with_backend_key(transaction, secret_key: str):
    """Signs a transaction with a backend-managed secret key."""
    try:
        source_keypair = Keypair.from_secret(secret_key)
        transaction.sign(source_keypair)
        return transaction
    except Exception as e:
        print(f"Error signing transaction: {e}")
        return None

# Example usage:
# app_secret = get_app_secret_key()
# signed_transaction = sign_transaction_with_backend_key(transaction_to_sign, app_secret)