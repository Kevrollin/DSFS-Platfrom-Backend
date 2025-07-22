# Assuming 'server' is initialized from 2.1.2
import asyncio
from stellar_sdk.exceptions import NotFoundError

async def check_transaction_status(transaction_hash: str, max_attempts: int = 10, delay_seconds: int = 5):
    """Checks the status of a transaction by polling Horizon."""
    for attempt in range(max_attempts):
        try:
            transaction_record = await server.transactions().transaction_id(transaction_hash).call()
            print(f"Transaction {transaction_hash} status: Success")
            # Transaction found means it was successful
            return {"status": "success", "record": transaction_record}
        except NotFoundError:
            print(f"Attempt {attempt+1}: Transaction {transaction_hash} not yet found.")
            await asyncio.sleep(delay_seconds) # Wait before next attempt
        except Exception as e:
            print(f"Attempt {attempt+1}: Error checking transaction status: {e}")
            await asyncio.sleep(delay_seconds)

    print(f"Transaction {transaction_hash} not confirmed after {max_attempts} attempts.")
    # At this point, you might consider it failed or require manual investigation
    return {"status": "not_found_after_attempts", "record": None}

# Example usage after submitting:
# if submission_result["successful"]:
#     monitor_result = await check_transaction_status(submission_result["hash"])
#     if monitor_result["status"] == "success":
#         # Update database, notify user etc.
#         pass
#     else:
#         # Handle unconfirmed transaction
#         pass