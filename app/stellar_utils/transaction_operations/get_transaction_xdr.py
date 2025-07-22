# Assuming 'transaction' is built from 2.3.4
def get_transaction_xdr(transaction):
    """Returns the transaction in XDR format for client signing."""
    return transaction.to_xdr()

# Example usage (in your FastAPI endpoint for direct funding):
# transaction_for_donor = await build_transaction(...)
# if transaction_for_donor:
#     xdr = get_transaction_xdr(transaction_for_donor)
#     return {"message": "Transaction ready for signing.", "stellar_transaction_xdr": xdr}