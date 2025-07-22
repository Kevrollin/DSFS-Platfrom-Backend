# app/routes/student_transactions.py

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from stellar_sdk import Optional

from app.stellar_utils.account_management.get_account_balances import get_account_balances
# Import necessary modules
from ..core.database import Database
from ..core.auth import get_current_user # Assuming this fetches the User model with keys
from ..models.models import User, UserRole
# Import decryption and transaction sending functions
from ..stellar_utils.key_security import decrypt_secret_key
from ..stellar_utils.transaction_operations.transaction_operations import send_stellar_payment # Assuming this is where send_stellar_payment is


router = APIRouter()

# Pydantic model for the request body when sending XLM
class SendXlmRequest(BaseModel):
    destination_public_key: str
    amount: float # Allow float input, convert to string for Stellar
    memo_text: Optional[str] = None # Optional memo

@router.post("/student/send_xlm", status_code=status.HTTP_200_OK)
async def student_send_xlm(
    request_data: SendXlmRequest,
    current_user: User = Depends(get_current_user) # Authenticate user
):
    # Ensure the authenticated user is a student
    if current_user.role != UserRole.STUDENT:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only students can send XLM from their accounts."
        )

    # Ensure the user has a Stellar secret key stored
    if not current_user.stellar_secret_key_encrypted:
         raise HTTPException(
             status_code=status.HTTP_400_BAD_REQUEST,
             detail="Your account does not have a Stellar secret key associated or it was not stored."
         )

    # --- Decrypt the student's secret key ---
    try:
        source_secret = decrypt_secret_key(current_user.stellar_secret_key_encrypted)
        if not source_secret:
             raise ValueError("Decrypted secret key is empty.")
    except Exception as e:
        # Handle decryption errors (e.g., invalid key, corrupted data)
        print(f"Error decrypting secret key for user {current_user.email}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to access your Stellar account securely."
        )
    # ------------------------------------------

    # --- Send the Stellar payment ---
    # Ensure amount is a string for Stellar SDK
    amount_str = str(request_data.amount)

    print(f"User {current_user.email} attempting to send {amount_str} XLM to {request_data.destination_public_key}")

    transaction_result = await send_stellar_payment(
        source_secret=source_secret,
        destination_public=request_data.destination_public_key,
        amount=amount_str,
        asset_code="XLM", # Hardcoded for sending XLM
        memo_text=request_data.memo_text
    )
    # -----------------------------------

    # Process the transaction result
    if transaction_result["successful"]:
        # You might want to log this transaction in your database
        # db = Database.get_db()
        # await db["transactions"].insert_one({
        #     "donor_id": current_user.id, # Or link as sender_id
        #     "recipient_wallet": request_data.destination_public_key,
        #     "amount": request_data.amount,
        #     "asset_type": "XLM",
        #     "transaction_hash": transaction_result["hash"],
        #     "status": "successful", # Or "pending" if monitoring is needed
        #     "created_at": datetime.utcnow(),
        #     # ... other relevant fields
        # })

        return {
            "message": "Transaction submitted successfully.",
            "transaction_hash": transaction_result["hash"]
        }
    else:
        # Handle transaction submission failure
        print(f"Transaction failed for user {current_user.email}: {transaction_result.get('error')}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, # Or 500 depending on the error type
            detail=f"Transaction failed: {transaction_result.get('error', 'Unknown error')}",
            headers={"X-Stellar-Result-Codes": str(transaction_result.get('result_codes'))} # Include Stellar specific error codes
        )
        
        
@router.get("/student/balance", status_code=status.HTTP_200_OK)
async def get_student_balance(
    current_user: User = Depends(get_current_user)
):
    # 🚫 Ensure only students can access
    if current_user.role != UserRole.STUDENT:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only students can access this route."
        )

    # 🧪 Ensure the student has a Stellar public key
    if not current_user.stellar_public_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No Stellar public key associated with this account."
        )

    # 🔁 Fetch balance
    try:
        balances = get_account_balances(current_user.stellar_public_key)
        if balances is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Stellar account not found or balance not retrievable."
            )

        # 🎯 Format response nicely
        formatted_balances = []
        for bal in balances:
            formatted_balances.append({
                "asset_type": bal.asset_type,
                "asset_code": bal.asset_code if hasattr(bal, "asset_code") else "XLM",
                "balance": bal.balance
            })

        return {
            "public_key": current_user.stellar_public_key,
            "balances": formatted_balances
        }

    except Exception as e:
        print(f"Error retrieving balance for {current_user.email}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not fetch account balance. Try again later."
        )