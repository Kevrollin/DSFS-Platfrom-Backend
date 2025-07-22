# Assuming 'server' and 'NETWORK_PASSPHRASE' are initialized from 2.1.2
from stellar_sdk import TransactionBuilder, server, NETWORK_PASSPHRASE
from stellar_sdk.exceptions import NotFoundError

async def build_transaction(source_public_key: str, operations: list, memo=None, timeout: int = 30):
    """Builds a transaction from a list of operations."""
    try:
        # 1. Load the source account to get its sequence number
        source_account = await server.load_account(account_id=source_public_key)

        # Get the base fee from Horizon
        base_fee = await server.fetch_base_fee()

        # 2. Create a TransactionBuilder
        transaction_builder = (
            TransactionBuilder(
                source_account=source_account,
                opts={
                    "fee": base_fee,
                    "network_passphrase": NETWORK_PASSPHRASE,
                    "timeout": timeout,
                },
            )
        )

        # 3. Add operations
        for op in operations:
            transaction_builder.add_operation(op)

        # 4. Set memo if provided
        if memo:
            from stellar_sdk import Memo
            # You can use Memo.text, Memo.id, Memo.hash
            transaction_builder.add_memo(Memo.text(memo))

        # 5. Build the transaction
        transaction = transaction_builder.build()

        return transaction

    except NotFoundError:
        print(f"Source account {source_public_key} not found on the network.")
        return None
    except Exception as e:
        print(f"Error building transaction: {e}")
        return None

# Example usage (assuming you have operations like payment_op):
# source_account_public_key = get_app_public_key() # Get your app's public key
# ops = [payment_op] # List of operations
# transaction_to_sign = await build_transaction(source_account_public_key, ops)
# if transaction_to_sign:
#     print("Transaction built successfully.")