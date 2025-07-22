from fastapi import APIRouter, HTTPException, Depends
from bson import ObjectId
from ..models.models import User
from ..schemas.schemas import UserCreate, UserResponse
from ..core.database import Database

router = APIRouter()

@router.post("/", response_model=UserResponse)
async def create_user(user: UserCreate):
    db = Database.get_db()
    if await db["users"].find_one({"email": user.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user_dict = user.dict()
    result = await db["users"].insert_one(user_dict)
    
    created_user = await db["users"].find_one({"_id": result.inserted_id})
    if created_user is None:
        raise HTTPException(status_code=500, detail="Failed to create user")
    
    # Convert ObjectId to string before returning
    created_user["_id"] = str(created_user["_id"])
    return UserResponse(**created_user)

@router.get("/{user_id}", response_model=UserResponse)
async def get_user(user_id: str):
    try:
        db = Database.get_db()
        user = await db["users"].find_one({"_id": ObjectId(user_id)})
        if user is None:
            raise HTTPException(status_code=404, detail="User not found")
        return user
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))