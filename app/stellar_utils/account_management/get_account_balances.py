# Assuming 'server' is initialized from 2.1.2
from stellar_sdk.exceptions import NotFoundError
from stellar_sdk import Server, Keypair, TransactionBuilder, Network, Asset
from stellar_sdk.exceptions import NotFoundError

# Horizon & Network config
HORIZON_URL = "https://horizon-testnet.stellar.org"
NETWORK_PASSPHRASE = Network.TESTNET_NETWORK_PASSPHRASE 
def get_account_balances(account_id: str):
    """Queries the balances for a given Stellar account ID."""
    try:
        server = Server(horizon_url=HORIZON_URL)
        account = server.load_account(account_id=account_id)
        balances = account.balances
        return balances # This is a list of Balance objects
    except NotFoundError:
        print(f"Account {account_id} not found on the network.")
        return None
    except Exception as e:
        print(f"Error fetching account balances: {e}")
        return None

# Example usage:
# student_public_key = "GBKXKXVHTUDKBI6MZPEWBJIO6PNIJHU5XAYWAPO25TM3JQEFZGBW6KLE" # Get from your database
# account_info = get_account_balances(student_public_key)
# if account_info:
#     for balance in account_info:
#         print(f"Asset: {balance.asset_code}, Balance: {balance.balance}")