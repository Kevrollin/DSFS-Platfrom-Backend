from stellar_sdk import Asset, Keypair, Server, TransactionBuilder, Network

# Load Stellar testnet horizon server
server = Server(horizon_url="https://horizon-testnet.stellar.org")

# 1. Source account (you MUST keep the secret key safe)
source_secret = "SAI75GAPTCHVB4Y6FZVDGMOOZTEKXAXBFLY73HDQO6I5T3M3YPA5U2VT"  # replace with your real secret
source_keypair = Keypair.from_secret(source_secret)
source_public = source_keypair.public_key

# 2. Destination account (must exist)
destination_public = "GAUXE5SUSP4UVXRUSXQXINHNEYHUIZZGIS2IWDPTJL33NFNILABCZ6V7"  # replace with actual destination address

# 3. Load the source account from the blockchain
source_account = server.load_account(account_id=source_public)

# 4. Build transaction
transaction = (
    TransactionBuilder(
        source_account=source_account,
        network_passphrase=Network.TESTNET_NETWORK_PASSPHRASE,
        base_fee=100,  # minimum base fee is 100 stroops
    )
    .add_text_memo("Test payment")  # optional memo
    .append_payment_op(destination=destination_public, amount="10", asset=Asset.native())
    .set_timeout(30)
    .build()
)

# 5. Sign the transaction with the source account
transaction.sign(source_keypair)

# 6. Submit the transaction
response = server.submit_transaction(transaction)

print("✅ Transaction successful!")
print("Transaction hash:", response["hash"])
