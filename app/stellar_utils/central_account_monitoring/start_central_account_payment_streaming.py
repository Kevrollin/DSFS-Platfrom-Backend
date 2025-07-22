# Assuming 'server' is initialized from 2.1.2 and 'get_app_public_key()' exists
# This would typically run in a separate background process or task
import asyncio
import json # For pretty printing

def start_central_account_payment_streaming():
    """Starts streaming incoming payments to the central application account."""
    central_account_id = get_app_public_key()
    # Start from the last processed payment cursor or 'now'
    # You MUST persist this cursor in your database to avoid reprocessing payments
    last_processed_cursor = "now" # Load this from your DB

    def process_payment(response):
        # This function is called for each new payment received by the central account
        print(f"Incoming Payment to Central Account: {json.dumps(response, indent=2)}")
        # Check if the destination is your central account and the source is not yourself
        if response['to'] == central_account_id and response['from'] != central_account_id:
            print(f"Received donation from {response['from']} for {response['amount']} {response['asset_code']}")
            # *** Trigger your funding algorithm or add the amount to a queue ***
            # You would likely add this payment information to a queue or database
            # for your separate funding algorithm process to pick up.
            # Save response['paging_token'] as the last processed cursor
            # save_last_processed_cursor(response['paging_token'])

    def on_error(exception):
        print(f"Central account payment streaming error: {exception}")
        # Handle errors, potentially reconnect the stream after a delay

    print(f"Starting incoming payment stream for central account {central_account_id}...")
    # Use .payments() instead of .transactions()
    return server.payments().for_account(central_account_id).cursor(last_processed_cursor).stream(process_payment, on_error)

# To run this in the background (requires a separate mechanism like asyncio or a task queue):
# loop = asyncio.get_event_loop()
# stream = loop.run_in_executor(None, start_central_account_payment_streaming)
# In a production FastAPI app, you might use a background task runner like Celery or FastAPI's background tasks (for simpler cases).