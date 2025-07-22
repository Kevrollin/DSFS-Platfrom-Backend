import os
# You might need a library to load environment variables, like python-dotenv
# from dotenv import load_dotenv
# load_dotenv() # Load variables from a .env file in development

def get_app_secret_key():
    """Retrieves the application's Stellar secret key securely."""
    # Get from environment variable
    secret_key = os.getenv("APP_STELLAR_SECRET_KEY")
    if not secret_key:
        raise ValueError("APP_STELLAR_SECRET_KEY environment variable not set.")
    # You might add validation here to ensure it's a valid secret key format
    return secret_key

# Example usage (in a function that needs the secret key):
# app_secret = get_app_secret_key()
# app_keypair = Keypair.from_secret(app_secret)