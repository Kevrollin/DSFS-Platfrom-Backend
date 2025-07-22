import logging
from stellar_sdk import Account, Asset, Keypair, Network, TransactionBuilder, exceptions

# ------------------------
# 🎯 Setup Logging
# ------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("stellar_transaction.log"),
        logging.StreamHandler()
    ]
)

# ------------------------
# 🔧 Configurations
# ------------------------
SECRET_KEY = "SAI75GAPTCHVB4Y6FZVDGMOOZTEKXAXBFLY73HDQO6I5T3M3YPA5U2VT"
DESTINATION_ADDRESS = "GAUXE5SUSP4UVXRUSXQXINHNEYHUIZZGIS2IWDPTJL33NFNILABCZ6V7"
HOME_DOMAIN = "overcat.me"
STARTING_SEQUENCE = 1
AMOUNT_TO_SEND = "125.5"
BASE_FEE = 100
TIMEOUT = 30


def build_transaction():
    try:
        # 🔐 Generate keypair from secret
        logging.info("Generating keypair from secret.")
        root_keypair = Keypair.from_secret(SECRET_KEY)
        root_public_key = root_keypair.public_key

        # 🧾 Create Account object
        logging.info("Creating Account object with sequence number %s.", STARTING_SEQUENCE)
        root_account = Account(account=root_public_key, sequence=STARTING_SEQUENCE)

        # 🧱 Build transaction
        logging.info("Building transaction with payment and set_options operations.")
        transaction = (
            TransactionBuilder(
                source_account=root_account,
                network_passphrase=Network.TESTNET_NETWORK_PASSPHRASE,
                base_fee=BASE_FEE
            )
            .append_payment_op(
                destination=DESTINATION_ADDRESS,
                asset=Asset.native(),
                amount=AMOUNT_TO_SEND
            )
            .append_set_options_op(
                home_domain=HOME_DOMAIN
            )
            .set_timeout(TIMEOUT)
            .build()
        )

        logging.info("Transaction successfully built.")
        return transaction

    except exceptions.Ed25519SecretSeedInvalidError:
        logging.error("Invalid Stellar secret key.")
    except Exception as e:
        logging.exception("An error occurred while building the transaction: %s", str(e))


if __name__ == "__main__":
    tx = build_transaction()
    if tx:
        logging.info("Transaction XDR: %s", tx.to_xdr())
