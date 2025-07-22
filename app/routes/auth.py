# app/routes/auth.py

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from ..core.auth import (
    verify_password,
    create_access_token,
    get_password_hash,
    get_current_user,
    get_current_admin,
    ACCESS_TOKEN_EXPIRE_MINUTES
)
# Import your updated User model
from ..models.models import User, UserBase, UserRole, StudentProfile, DonorProfile
from ..core.database import Database
from datetime import timedelta
# Import key generation and security functions
from ..stellar_utils.key_security import generate_stellar_keypair, encrypt_secret_key
# Import funding function (implement this next, potentially in account_management)
from ..stellar_utils.account_management.fund_testnet_account  import fund_testnet_account # Assuming Testnet for now

# from app.utils.fund_testnet_account import fund_testnet_account

router = APIRouter()

@router.post("/register")
async def signup(user: UserBase):
    db = Database.get_db()

    # Check if email is already registered
    if await db["users"].find_one({"email": user.email}):
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )

    # --- Generate and Encrypt Stellar Keypair ---
    try:
        stellar_keys = generate_stellar_keypair()
        encrypted_secret = encrypt_secret_key(stellar_keys["secret_key"])
        public_key = stellar_keys["public_key"]
    except Exception as e:
        # Handle errors during key generation or encryption
        print(f"Error during Stellar key generation or encryption: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate Stellar account."
        )
    # ---------------------------------------------

    # Prepare user data for database insertion
    user_dict = user.dict()
    user_dict["password_hash"] = get_password_hash(user_dict.pop("password"))
    user_dict["role"] = UserRole.STUDENT.value # Set default role to STUDENT

    # Add Stellar keys to the user data
    user_dict["stellar_public_key"] = public_key
    user_dict["stellar_secret_key_encrypted"] = encrypted_secret

    # Initialize profile based on role (assuming student for registration for now)
    if user_dict["role"] == UserRole.STUDENT.value:
        # You'll need to collect student profile details during registration or later
        # For now, let's assume UserBase includes basic student profile data or it's added separately
        # Example: If UserBase included institution, year_of_study, etc.
        # student_profile_data = {
        #     "institution": user_dict.pop("institution"),
        #     "year_of_study": user_dict.pop("year_of_study"),
        #     # ... other student fields
        # }
        # user_dict["student_profile"] = StudentProfile(**student_profile_data).dict()
        # If student profile is added later, initialize as None or a basic structure
        user_dict["student_profile"] = None # Assuming profile details are added later


    # Insert the new user into the database
    try:
        result = await db["users"].insert_one(user_dict)
        created_user = await db["users"].find_one({"_id": result.inserted_id})
    except Exception as e:
        print(f"Error inserting user into database: {e}")
        # Consider compensating (e.g., logging that a keypair was generated but user not saved)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user."
        )

    # --- Fund the newly created Stellar account ---
    # This operation should ideally be handled in a robust background task
    # For a simple start, we can call it directly, but be aware of potential delays/failures
    # Assuming Testnet funding via Friendbot
    funding_success = await fund_testnet_account(public_key) # Implement this function

    if not funding_success:
        print(f"Warning: Failed to fund new account {public_key} on Testnet.")
        # Decide how to handle funding failures (e.g., mark account as unfunded, notify admin)
        pass # Continue registration even if funding fails initially

    # --------------------------------------------

    # Return a response (do NOT include the secret key)
    return {
        "email": created_user["email"],
        "username": created_user["username"],
        "stellar_public_key": created_user.get("stellar_public_key"), # Include public key
        "message": "User created successfully. Stellar account generated."
    }

# The login and read_users_me endpoints can remain largely the same,
# as they should not return the secret key.
# The User model loaded by get_current_user will include the public key.

@router.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    db = Database.get_db()
    # Fetch user, potentially including stellar_public_key and encrypted_secret_key
    user = await db["users"].find_one({"email": form_data.username})

    if not user or not verify_password(form_data.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Create access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["email"]}, expires_delta=access_token_expires
    )

    # Return access token and user's public key (optional, but useful for frontend)
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "stellar_public_key": user.get("stellar_public_key") # Include public key in login response
    }

@router.get("/me")
async def read_users_me(current_user: User = Depends(get_current_user)):
    # The current_user object derived from the token will have the public key loaded from DB
    # Ensure your get_current_user logic fetches all necessary user fields from the DB
    return current_user