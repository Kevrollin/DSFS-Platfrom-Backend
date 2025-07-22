from stellar_sdk import Server, Keypair, TransactionBuilder, Payment, Network, Asset
# Removing SubmitTransactionError import as it consistently fails in your environment
from stellar_sdk.exceptions import NotFoundError

# --- Configuration ---

# Your personal account public key (source)
SOURCE_PUBLIC_KEY = "GA2ZEGMMECSVHJPGEVJQN5ZLNL6R7HRE26EB7EWADBKJCPUUR35J5DUF"

# The destination account public key
DESTINATION_PUBLIC_KEY = "GAUXE5SUSP4UVXRUSXQXINHNEYHUIZZGIS2IWDPTJL33NFNILABCZ6V7"

# Amount to send (as a string)
AMOUNT_TO_SEND = "10.0"

# Asset to send (XLM in this case)
# This should work with stellar-sdk 12.2.1
ASSET_TO_SEND = Asset.native() # Represents native XLM

# !!! Your SECRET KEY !!!
# Replace with your actual secret key.
# For security, load this from an environment variable or secure storage,
# DO NOT hardcode your secret key directly in your final application code!
SOURCE_SECRET_KEY = "SAI75GAPTCHVB4Y6FZVDGMOOZTEKXAXBFLY73HDQO6I5T3M3YPA5U2VT" # <<-- REPLACE THIS
# WARNING: Hardcoding secret keys is INSECURE. Use environment variables or secrets management.

# --- Network Configuration ---
# Choose the network: Testnet for testing, Public Network for real transactions

# Using string literal passphrases as Network attributes failed repeatedly in your environment
HORIZON_URL = "https://horizon-testnet.stellar.org"
NETWORK_PASSPHRASE = "Test SDF Network ; September 2015"

# For Public Network (uncomment the lines below and comment the Testnet ones to use):
# HORIZON_URL = "https://horizon.stellar.org"
# NETWORK_PASSPHRASE = "Public Global Stellar Network ; September 2015"


# --- Stellar Transaction Logic ---

async def send_xlm(source_secret: str, destination_public: str, amount: str):
    """Sends XLM from a source account to a destination account."""
    try:
        # Initialize Server
        server = Server(horizon_url=HORIZON_URL)
        # Attempt to use use_network_passphrase if it exists in your installation,
        # otherwise rely on the passphrase being passed in opts.
        try:
             # This line consistently failed in your environment, but might work after reinstall
             Network.use_network_passphrase(NETWORK_PASSPHRASE)
             print("Using Network.use_network_passphrase (if available)")
        except AttributeError:
             print("Network.use_network_passphrase not found in your installation.")
             # If use_network_passphrase doesn't exist, the passphrase *must* be in opts.


        # 1. Get the source account keypair from the secret key
        source_keypair = Keypair.from_secret(source_secret)
        # Verify the public key matches the configured source public key (optional but good practice)
        if source_keypair.public_key != SOURCE_PUBLIC_KEY:
             print("Error: Provided secret key does not match the configured source public key.")
             return None
        print(f"Using source public key derived from secret key: {source_keypair.public_key}")


        # 2. Load the source account from Horizon to get its current sequence number
        # The sequence number is crucial for transaction ordering and preventing replay attacks.
        # This requires 'await' for async methods in standard SDK
        source_account = await server.load_account(account_id=source_keypair.public_key)
        print(f"Source account loaded. Sequence number: {source_account.sequence}")

        # 3. Get the current base fee from Horizon
        # This is the minimum fee required per operation.
        # This requires 'await' for async methods in standard SDK
        base_fee = await server.fetch_base_fee()
        print(f"Base fee fetched: {base_fee}")

        # 4. Create a Payment operation
        payment_operation = Payment(
            destination=destination_public,
            asset=ASSET_TO_SEND,
            amount=amount
        )
        print("Payment operation created.")

        # 5. Build the transaction
        # Add the payment operation to the transaction
        transaction = (
            TransactionBuilder(
                source_account=source_account,
                opts={
                    "fee": base_fee,
                    # Passing passphrase via opts is essential if use_network_passphrase fails
                    "network_passphrase": NETWORK_PASSPHRASE,
                    "timeout": 30, # Set a reasonable timeout for the transaction
                },
            )
            .add_operation(payment_operation)
            .build()
        )
        print("Transaction built.")

        # 6. Sign the transaction with the source account's secret key
        transaction.sign(source_keypair)
        print("Transaction signed.")

        # 7. Submit the signed transaction to Horizon
        print("Submitting transaction to Horizon...")
        # Catch any exception during submission as SubmitTransactionError import fails
        response = await server.submit_transaction(transaction)

        print("\nTransaction successful!")
        print("Transaction Hash:", response['hash'])
        print("Ledger:", response['ledger'])
        return response['hash']

    except NotFoundError:
        print(f"Error: Source or destination account not found on the network. Ensure both accounts exist and are funded (min 1 XLM balance).")
        # Double check if the provided public key GA2ZEG... exists on the Testnet
        print(f"Check if account {source_keypair.public_key} exists on {HORIZON_URL}")
        print(f"Check if account {destination_public} exists on {HORIZON_URL}")
        return None
    except Exception as e: # Catch any exception during submission, including potential SubmitTransactionError
        print(f"An error occurred during transaction submission or processing: {e}")
        # Note: Cannot reliably access e.extras.result_codes here without
        # a successful SubmitTransactionError import or type check.
        # If the error was "object Account can't be used in 'await' expression",
        # it suggests a deep issue with your SDK installation or environment.
        return None

# --- Running the script ---
# Use asyncio to run the asynchronous function

import asyncio

async def main():
    print(f"Attempting to send {AMOUNT_TO_SEND} XLM from {SOURCE_PUBLIC_KEY} to {DESTINATION_PUBLIC_KEY}")
    print(f"Using network with passphrase: {NETWORK_PASSPHRASE}")


    # IMPORTANT: Make sure SOURCE_SECRET_KEY is set correctly and securely!
    if SOURCE_SECRET_KEY == "YOUR_PERSONAL_ACCOUNT_SECRET_KEY":
        print("\nERROR: Please replace 'YOUR_PERSONAL_ACCOUNT_SECRET_KEY' with your actual secret key.")
        print("       Do NOT hardcode your secret key in production applications.")
        return

    transaction_hash = await send_xlm(SOURCE_SECRET_KEY, DESTINATION_PUBLIC_KEY, AMOUNT_TO_SEND)

    if transaction_hash:
        print(f"\nTransaction completed. Check status on a Stellar explorer:")
        # Cannot reliably determine explorer URL using Network attributes
        print(f"Check manually on a Stellar explorer (e.g., https://testnet.stellarexpert.io/ or https://stellarexpert.io/) using transaction hash: {transaction_hash}")


if __name__ == "__main__":
    asyncio.run(main()) 