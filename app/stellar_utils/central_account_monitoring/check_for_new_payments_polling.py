# Assuming 'server' is initialized from 2.1.2 and 'get_app_public_key()' exists
import time

def check_for_new_payments_polling(last_cursor: str):
    """Checks for new incoming payments to the central account using polling."""
    central_account_id = get_app_public_key()
    try:
        # Fetch payments since the last cursor, ordered ascending
        payments_page = server.payments().for_account(central_account_id).cursor(last_cursor).order("asc").call()

        new_payments = payments_page['records']
        if new_payments:
            print(f"Found {len(new_payments)} new payments.")
            for payment in new_payments:
                 if payment['to'] == central_account_id and payment['from'] != central_account_id:
                    print(f"Received donation from {payment['from']} for {payment['amount']} {payment['asset_code']}")
                    # *** Trigger your funding algorithm or add the amount to a queue ***
                    # Update last_cursor to the paging_token of the last processed payment
                    last_cursor = payment['paging_token']
                    # Save the new last_cursor to your database immediately

        return last_cursor # Return the updated cursor

    except NotFoundError:
         # Account might not be found if not yet on ledger, handle appropriately
         print(f"Central account {central_account_id} not found on the network.")
         return last_cursor # Return the same cursor
    except Exception as e:
        print(f"Error during payment polling: {e}")
        return last_cursor # Return the same cursor in case of error

# To run this periodically (needs a background task mechanism):
# last_processed_cursor = "now" # Load from DB on startup
# while True:
#     last_processed_cursor = check_for_new_payments_polling(last_processed_cursor)
#     time.sleep(60) # Check every 60 seconds (adjust as needed)