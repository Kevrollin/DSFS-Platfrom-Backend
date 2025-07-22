# Assuming 'server' is initialized from 2.1.2
# This would typically run in a separate background process or task
def start_account_transaction_streaming(account_id: str):
    """Starts streaming transactions for a given account."""
    # Use a cursor to start from a specific point (e.g., 'now' or last processed)
    # You'll need to manage the cursor's persistence to avoid processing duplicates
    cursor = "now" # Or load the last processed cursor from your database

    def process_transaction(response):
        # This function is called for each new transaction involving the account
        print(f"Received transaction for {account_id}: {response['hash']}")
        # Here you would update your database, trigger events, etc.
        # Remember to save the cursor (response['paging_token']) periodically

    def on_error(exception):
        print(f"Streaming error for {account_id}: {exception}")
        # Handle errors, potentially reconnect

    print(f"Starting transaction stream for {account_id}...")
    return server.transactions().for_account(account_id).cursor(cursor).stream(process_transaction, on_error)

# Example usage (might run in a separate thread or process):
# stream = start_account_transaction_streaming(your_app_public_key)
# To stop streaming: stream.close()