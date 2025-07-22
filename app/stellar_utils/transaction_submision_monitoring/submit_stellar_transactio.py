# Assuming 'server' is initialized from 2.1.2
from stellar_sdk import server
from stellar_sdk.exceptions import SubmitTransactionError

async def submit_stellar_transaction(signed_transaction):
    """Submits a signed transaction to the Stellar network."""
    try:
        response = await server.submit_transaction(signed_transaction)
        print(f"Transaction submitted successfully: {response['hash']}")
        return {"hash": response['hash'], "successful": True}
    except SubmitTransactionError as e:
        print(f"Transaction submission failed: {e.message}")
        # You can inspect e.extras.result_codes for more details
        return {"hash": None, "successful": False, "error": e.message, "result_codes": e.extras.result_codes}
    except Exception as e:
        print(f"An unexpected error occurred during submission: {e}")
        return {"hash": None, "successful": False, "error": str(e), "result_codes": None}

# Example usage:
# if signed_transaction:
#     submission_result = await submit_stellar_transaction(signed_transaction)
#     if submission_result["successful"]:
#         print("Transaction confirmed on the ledger!")
#         # Update your database with the transaction hash and status
#     else:
#         print("Transaction failed. Details:", submission_result)
#         # Log the error and inform the user/admin