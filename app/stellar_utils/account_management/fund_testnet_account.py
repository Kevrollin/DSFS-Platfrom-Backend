import httpx
from httpx import HTTPError  # Catch errors from httpx if needed

async def fund_testnet_account(public_key: str):
    """Asynchronously funds a Testnet account using Friendbot."""
    friendbot_url = f"https://friendbot.stellar.org/?addr={public_key}"
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(friendbot_url)
            response.raise_for_status()
            print(f"Friendbot response: {response.json()}")
            return True
    except HTTPError as e:
        print(f"Error funding account with Friendbot: {e}")
        return False
