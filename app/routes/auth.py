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
from ..models.models import User, UserBase, UserRole, StudentProfile, DonorProfile, RegisterUser, RegisterDonor
from ..core.database import Database
from datetime import timedelta, datetime
# Import key generation and security functions
from ..stellar_utils.key_security import generate_stellar_keypair, encrypt_secret_key
# Import funding function (implement this next, potentially in account_management)
from ..stellar_utils.account_management.fund_testnet_account  import fund_testnet_account # Assuming Testnet for now
from pydantic import BaseModel
from typing import Optional

# from app.utils.fund_testnet_account import fund_testnet_account

router = APIRouter()

class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    role: str
    stellar_public_key: Optional[str] = None
    first_name: Optional[str] = None

@router.post("/register")
async def signup(user: RegisterUser):
    db = Database.get_db()

    # Check if email or username is already registered
    if await db["users"].find_one({"email": user.email}):
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )
    if await db["users"].find_one({"username": user.username}):
        raise HTTPException(
            status_code=400,
            detail="Username already registered"
        )

    # --- Generate and Encrypt Stellar Keypair if not provided ---
    if user.stellar_wallet:
        public_key = user.stellar_wallet
        encrypted_secret = None
    else:
        try:
            stellar_keys = generate_stellar_keypair()
            encrypted_secret = encrypt_secret_key(stellar_keys["secret_key"])
            public_key = stellar_keys["public_key"]
        except Exception as e:
            print(f"Error during Stellar key generation or encryption: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to generate Stellar account."
            )
    # -----------------------------------------------------------

    # Prepare user data for database insertion
    user_dict = {
        "first_name": user.first_name,
        "last_name": user.last_name,
        "username": user.username,
        "email": user.email,
        "password_hash": get_password_hash(user.password),
        "role": UserRole.STUDENT.value,
        "stellar_public_key": public_key,
        "stellar_secret_key_encrypted": encrypted_secret,
        "stellar_wallet": user.stellar_wallet,
        "student_profile": {
            "school": user.school,
            "expected_graduation_year": user.expected_graduation_year,
            # You can add more fields here if needed
            "institution": user.school,  # For backward compatibility
            "year_of_study": user.expected_graduation_year,  # For backward compatibility
            "student_id": "",
            "field_of_study": "",
            "is_verified": False
        },
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
    }

    # Insert the new user into the database
    try:
        result = await db["users"].insert_one(user_dict)
        created_user = await db["users"].find_one({"_id": result.inserted_id})
    except Exception as e:
        print(f"Error inserting user into database: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user."
        )

    # --- Fund the newly created Stellar account if generated ---
    if not user.stellar_wallet:
        funding_success = await fund_testnet_account(public_key)
    if not funding_success:
        print(f"Warning: Failed to fund new account {public_key} on Testnet.")
            # Continue registration even if funding fails initially

    # ----------------------------------------------------------

    # Return a response (do NOT include the secret key or password)
    return {
        "email": created_user["email"],
        "username": created_user["username"],
        "first_name": created_user["first_name"],
        "last_name": created_user["last_name"],
        "stellar_public_key": created_user.get("stellar_public_key"),
        "school": created_user["student_profile"]["school"],
        "expected_graduation_year": created_user["student_profile"]["expected_graduation_year"],
        "message": "User created successfully. Stellar account generated."
    }

@router.post("/register/student")
async def register_student(user: RegisterUser):
    db = Database.get_db()
    # Check if email or username is already registered
    if await db["users"].find_one({"email": user.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    if await db["users"].find_one({"username": user.username}):
        raise HTTPException(status_code=400, detail="Username already registered")
    # --- Generate and Encrypt Stellar Keypair if not provided ---
    if user.stellar_wallet:
        public_key = user.stellar_wallet
        encrypted_secret = None
    else:
        try:
            stellar_keys = generate_stellar_keypair()
            encrypted_secret = encrypt_secret_key(stellar_keys["secret_key"])
            public_key = stellar_keys["public_key"]
        except Exception as e:
            print(f"Error during Stellar key generation or encryption: {e}")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to generate Stellar account.")
    # -----------------------------------------------------------
    user_dict = {
        "first_name": user.first_name,
        "last_name": user.last_name,
        "username": user.username,
        "email": user.email,
        "password_hash": get_password_hash(user.password),
        "role": UserRole.STUDENT.value,
        "stellar_public_key": public_key,
        "stellar_secret_key_encrypted": encrypted_secret,
        "stellar_wallet": user.stellar_wallet,
        "student_profile": {
            "school": user.school,
            "expected_graduation_year": user.expected_graduation_year,
            "institution": user.school,
            "year_of_study": user.expected_graduation_year,
            "student_id": "",
            "field_of_study": "",
            "is_verified": False
        },
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
    }
    try:
        result = await db["users"].insert_one(user_dict)
        created_user = await db["users"].find_one({"_id": result.inserted_id})
    except Exception as e:
        print(f"Error inserting user into database: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create user.")
    if not user.stellar_wallet:
        funding_success = await fund_testnet_account(public_key)
        if not funding_success:
            print(f"Warning: Failed to fund new account {public_key} on Testnet.")
    return {
        "email": created_user["email"],
        "username": created_user["username"],
        "first_name": created_user["first_name"],
        "last_name": created_user["last_name"],
        "stellar_public_key": created_user.get("stellar_public_key"),
        "school": created_user["student_profile"]["school"],
        "expected_graduation_year": created_user["student_profile"]["expected_graduation_year"],
        "role": created_user["role"],
        "message": "Student registered successfully. Stellar account generated."
    }

@router.post("/register/donor")
async def register_donor(user: RegisterDonor):
    db = Database.get_db()
    # Check if email is already registered
    if await db["users"].find_one({"email": user.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    # --- Generate and Encrypt Stellar Keypair ---
    try:
        stellar_keys = generate_stellar_keypair()
        encrypted_secret = encrypt_secret_key(stellar_keys["secret_key"])
        public_key = stellar_keys["public_key"]
    except Exception as e:
        print(f"Error during Stellar key generation or encryption: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to generate Stellar account.")
    # -----------------------------------------------------------
    user_dict = {
        "first_name": user.first_name,
        "last_name": user.last_name,
        "email": user.email,
        "password_hash": get_password_hash(user.password),
        "role": UserRole.DONOR.value,
        "stellar_public_key": public_key,
        "stellar_secret_key_encrypted": encrypted_secret,
        "donor_profile": {
            "organization": None,
            "preferred_categories": [],
            "donation_history": [],
            "total_donated": 0.0
        },
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
    }
    try:
        result = await db["users"].insert_one(user_dict)
        created_user = await db["users"].find_one({"_id": result.inserted_id})
    except Exception as e:
        print(f"Error inserting user into database: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create user.")
    return {
        "email": created_user["email"],
        "first_name": created_user["first_name"],
        "last_name": created_user["last_name"],
        "stellar_public_key": created_user.get("stellar_public_key"),
        "role": created_user["role"],
        "message": "Donor registered successfully. Stellar account generated."
    }

# The login and read_users_me endpoints can remain largely the same,
# as they should not return the secret key.
# The User model loaded by get_current_user will include the public key.

@router.post(
    "/login",
    response_model=LoginResponse,
    summary="Login (role-based)",
    description="Login for both students and donors. Returns JWT, user role, and first name."
)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    db = Database.get_db()
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
        data={"sub": user["email"], "role": user["role"]}, expires_delta=access_token_expires
    )

    # Return access token and user's public key (optional, but useful for frontend)
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "role": user["role"],
        "stellar_public_key": user.get("stellar_public_key"),
        "first_name": user.get("first_name"),
    }

@router.get("/me")
async def read_users_me(current_user: User = Depends(get_current_user)):
    # The current_user object derived from the token will have the public key loaded from DB
    # Ensure your get_current_user logic fetches all necessary user fields from the DB
    return current_user