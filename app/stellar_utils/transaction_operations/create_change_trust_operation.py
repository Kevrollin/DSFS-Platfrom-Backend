from stellar_sdk import Operation, Asset

def create_change_trust_operation(asset_code: str, asset_issuer: str, limit: str = None):
    """Creates a ChangeTrust operation to establish or modify a trustline."""
    asset = Asset(code=asset_code, issuer=asset_issuer)
    # limit can be a string representing the max amount or None for max limit
    return Operation.change_trust(
        asset=asset,
        limit=limit # e.g., "1000000000" or None
    )

# This operation would be part of a transaction signed by the student's account.