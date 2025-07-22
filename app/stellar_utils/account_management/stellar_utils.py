from stellar_sdk import Server, Network

# Define Horizon URLs
TESTNET_HORIZON_URL = "https://horizon-testnet.stellar.org"
PUBLIC_HORIZON_URL = "https://horizon.stellar.org"

# Choose your network and Horizon URL
# For development:
HORIZON_URL = TESTNET_HORIZON_URL
# NETWORK_PASSPHRASE = Network.TESTNET_PASSPHRASE

# # For production:
# HORIZON_URL = PUBLIC_HORIZON_URL
# NETWORK_PASSPHRASE = Network.PUBLIC_NETWORK_PASSPHRASE

# Initialize the Stellar Server
server = Server(horizon_url=HORIZON_URL)
# Network.use_network_passphrase(NETWORK_PASSPHRASE)

# You can now use 'server' and 'NETWORK_PASSPHRASE' throughout your application
# to interact with the chosen Stellar network.
