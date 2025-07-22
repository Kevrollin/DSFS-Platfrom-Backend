from stellar_sdk import Server

server = Server(horizon_url="https://horizon-testnet.stellar.org")

account = "GA2ZEGMMECSVHJPGEVJQN5ZLNL6R7HRE26EB7EWADBKJCPUUR35J5DUF"

# Fetch account details
account_data = server.accounts().account_id(account).call()

# Print balances
print(f"\nBalances for account {account}:")
for balance in account_data['balances']:
    print(f"Type: {balance['asset_type']}, Balance: {balance['balance']}")
