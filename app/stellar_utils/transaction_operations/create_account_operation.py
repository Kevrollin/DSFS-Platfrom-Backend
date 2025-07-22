from stellar_sdk import Operation

def create_create_account_operation(destination_public_key: str, starting_balance: str = "1.5"):
    """Creates a CreateAccount operation."""
    # starting_balance must be a string
    return Operation.create_account(
        account_id=destination_public_key,
        starting_balance=starting_balance
    )

# This operation is typically added to a transaction built by the funding account
# (your app's account or Friendbot on Testnet).