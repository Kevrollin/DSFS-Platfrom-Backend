from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from ..models.models import User, UserBase, UserRole
from .database import Database
import os
from dotenv import load_dotenv

load_dotenv()

# Security settings
SECRET_KEY = os.getenv("SECRET_KEY", "").strip()

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 300000

# Initial admin credentials
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@example.com")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "adminpassword123")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")

async def create_initial_admin():
    db = Database.get_db()
    # Check if admin exists
    if not await db["users"].find_one({"email": ADMIN_EMAIL}):
        admin_user = {
            "email": ADMIN_EMAIL,
            "username": ADMIN_USERNAME,
            "password_hash": pwd_context.hash(ADMIN_PASSWORD),
            "role": "admin",
            "is_verified": True,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }
        await db["users"].insert_one(admin_user)
        print("Initial admin user created")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

# def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
#     to_encode = data.copy()
#     expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
#     to_encode.update({"exp": expire})
#     encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
#     return encoded_jwt
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None,):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    # Must include 'sub'
    if "sub" not in to_encode:
        raise ValueError("Missing 'sub' claim in token data.")
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserBase:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    print("Received token:", token)

    try:
        print("Decoding token...")
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        print("Decoded payload:", payload)
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError as e:
        print("JWT Error:", str(e))  # <-- Add this
        raise credentials_exception


        
        
    except JWTError:
        raise credentials_exception
    
    db = Database.get_db()
    user = await db["users"].find_one({"email": email})
    if user is None:
        raise credentials_exception
    return User(**user)

async def get_current_admin(current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    return current_user

def require_student(current_user=Depends(get_current_user)):
    if current_user.role != UserRole.STUDENT:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Students only.")
    return current_user

def require_donor(current_user=Depends(get_current_user)):
    if current_user.role != UserRole.DONOR:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Donors only.")
    return current_user