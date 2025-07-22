# app/stellar_utils/stellar_transactions.py

from stellar_sdk import Server, Keypair, TransactionBuilder, Network, Asset
from stellar_sdk.exceptions import NotFoundError

# Horizon & Network config
HORIZON_URL = "https://horizon-testnet.stellar.org"
NETWORK_PASSPHRASE = Network.TESTNET_NETWORK_PASSPHRASE  # Equivalent to "Test SDF Network ; September 2015"

async def send_stellar_payment(
    source_secret: str,
    destination_public: str,
    amount: str,
    asset_code: str = "XLM",
    asset_issuer: str = None,
    memo_text: str = None
):
    """
    Sends a Stellar payment from a source account to a destination.
    """
    try:
        server = Server(horizon_url=HORIZON_URL)

        # 1. Load source keypair and account
        source_keypair = Keypair.from_secret(source_secret)
        source_public = source_keypair.public_key
        print(f"Using source public key: {source_public}")

        source_account = server.load_account(account_id=source_public)
        print(f"Source account loaded with sequence: {source_account.sequence}")

        # 2. Define asset
        if asset_code == "XLM":
            asset_to_send = Asset.native()
        else:
            if not asset_issuer:
                raise ValueError("Asset issuer must be provided for non-XLM assets.")
            asset_to_send = Asset(code=asset_code, issuer=asset_issuer)

        # 3. Start building transaction
        tx_builder = TransactionBuilder(
            source_account=source_account,
            network_passphrase=NETWORK_PASSPHRASE,
            base_fee=100
        )

        # 4. Add memo if provided
        if memo_text:
            tx_builder.add_text_memo(memo_text)

        # 5. Add payment operation
        tx_builder.append_payment_op(
            destination=destination_public,
            asset=asset_to_send,
            amount=amount
        )

        # 6. Set timeout and build
        tx_builder.set_timeout(30)
        transaction = tx_builder.build()

        # 7. Sign
        transaction.sign(source_keypair)
        print("Transaction signed and built.")

        # 8. Submit transaction
        print("Submitting transaction...")
        try:
            response = server.submit_transaction(transaction)  # remove `await` unless using async SDK
            print("Transaction successful!")
            print("Hash:", response["hash"])
            print("Ledger:", response["ledger"])

            return {
                "hash": response["hash"],
                "successful": True,
                "error": None,
                "result_codes": None
            }

        except Exception as e:
            print(f"Submission error: {e}")
            return {
                "hash": None,
                "successful": False,
                "error": str(e),
                "result_codes": None
            }

    except NotFoundError:
        print(f"Account not found: source={source_public} or destination={destination_public}")
        return {
            "hash": None,
            "successful": False,
            "error": "Account not found or not funded."
        }
    except Exception as e:
        print(f"Error during transaction setup: {e}")
        return {
            "hash": None,
            "successful": False,
            "error": str(e)
        }
