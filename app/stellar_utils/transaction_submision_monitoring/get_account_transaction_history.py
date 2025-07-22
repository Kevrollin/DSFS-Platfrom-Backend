# Assuming 'server' is initialized from 2.1.2
from stellar_sdk.exceptions import NotFoundError

def get_account_transaction_history(account_id: str, limit: int = 10, order: str = "desc"):
    """Retrieves transaction history for a given Stellar account ID."""
    try:
        # You can paginate results using .cursor() if needed
        operations_page = server.transactions().for_account(account_id).limit(limit).order(order).call()
        # The response contains 'records' which are the transactions
        transactions = operations_page['records']
        return transactions
    except NotFoundError:
        print(f"Account {account_id} not found on the network.")
        return None
    except Exception as e:
        print(f"Error fetching transaction history: {e}")
        return None

# Example usage:
# history = get_account_transaction_history(student_public_key)
# if history:
#     for tx in history:
#         print(f"Tx Hash: {tx['hash']}, Created At: {tx['created_at']}")
        # You might want to fetch the operations within each transaction for detail