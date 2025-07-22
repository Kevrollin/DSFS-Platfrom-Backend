from fastapi import APIRouter, Depends, HTTPException, Query
from ..core.auth import get_current_admin
from ..core.database import Database
from ..models.models import User
from bson import ObjectId
from enum import Enum
from typing import List, Optional
from datetime import datetime

class UserRole(str, Enum):
    ADMIN = "admin"
    DONOR = "donor"
    STUDENT = "student"

router = APIRouter()

@router.get("/users")
async def list_users(
    role: Optional[UserRole] = None,
    current_admin: User = Depends(get_current_admin)
) -> List[dict]:
    db = Database.get_db()
    filter_query = {"role": role} if role else {}
    users = await db["users"].find(filter_query).to_list(length=None)
    return users

@router.get("/users/detailed")
async def get_detailed_users(
    role: Optional[UserRole] = None,
    current_admin: User = Depends(get_current_admin)
):
    db = Database.get_db()
    pipeline = [
        {"$match": {"role": role.value} if role else {}},
        {
            "$lookup": {
                "from": "projects",
                "localField": "_id",
                "foreignField": "creator_id",
                "as": "projects"
            }
        },
        {
            "$lookup": {
                "from": "transactions",
                "localField": "wallet_address",
                "foreignField": "recipient_wallet",
                "as": "received_donations"
            }
        }
    ]
    users = await db["users"].aggregate(pipeline).to_list(length=None)
    return users

@router.post("/make-admin/{user_id}")
async def make_admin(user_id: str, admin: User = Depends(get_current_admin)):
    db = Database.get_db()
    await db["users"].update_one(
        {"_id": user_id},
        {"$set": {"role": "admin"}}
    )
    return {"message": "User role updated to admin"}

@router.post("/promote/{user_id}")
async def promote_to_admin(
    user_id: str,
    current_admin: User = Depends(get_current_admin)
):
    db = Database.get_db()
    user = await db["users"].find_one({"_id": ObjectId(user_id)})
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user["role"] == "admin":
        raise HTTPException(status_code=400, detail="User is already an admin")
    
    await db["users"].update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"role": "admin"}}
    )
    
    return {"message": f"User {user['email']} has been promoted to admin"}

@router.post("/change-role/{user_id}")
async def change_user_role(
    user_id: str,
    role: UserRole,
    current_admin: User = Depends(get_current_admin)
):
    db = Database.get_db()
    user = await db["users"].find_one({"_id": ObjectId(user_id)})
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user["role"] == role:
        raise HTTPException(status_code=400, detail=f"User is already a {role}")
    
    if user["role"] == "admin" and current_admin.email != user["email"]:
        raise HTTPException(
            status_code=403, 
            detail="Cannot change role of other admin users"
        )
    
    await db["users"].update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"role": role}}
    )
    
    return {"message": f"User {user['email']} role changed to {role}"}

@router.get("/stats")
async def get_stats(current_admin: User = Depends(get_current_admin)):
    db = Database.get_db()
    stats = {
        "total_users": await db["users"].count_documents({}),
        "total_admins": await db["users"].count_documents({"role": "admin"}),
        "total_donors": await db["users"].count_documents({"role": "donor"}),
        "total_students": await db["users"].count_documents({"role": "student"}),
        "total_projects": await db["projects"].count_documents({}),
        "total_transactions": await db["transactions"].count_documents({})
    }
    return stats

@router.get("/dashboard")
async def get_admin_dashboard(current_admin: User = Depends(get_current_admin)):
    db = Database.get_db()
    
    # Get basic stats
    basic_stats = await get_stats(current_admin)
    
    # Get recent activities
    recent_activities = {
        "new_users": await db["users"]
            .find()
            .sort("created_at", -1)
            .limit(5)
            .to_list(length=None),
            
        "recent_projects": await db["projects"]
            .find()
            .sort("created_at", -1)
            .limit(5)
            .to_list(length=None),
            
        "recent_donations": await db["transactions"]
            .find({"type": "donation"})
            .sort("created_at", -1)
            .limit(5)
            .to_list(length=None)
    }
    
    # Get verification requests
    pending_verifications = await db["users"].count_documents({
        "role": "student",
        "is_verified": False
    })
    
    return {
        "stats": basic_stats,
        "recent_activities": recent_activities,
        "pending_verifications": pending_verifications
    }

@router.get("/projects/student/{student_id}")
async def get_student_projects(
    student_id: str,
    current_admin: User = Depends(get_current_admin)
):
    db = Database.get_db()
    pipeline = [
        {"$match": {"creator_id": ObjectId(student_id)}},
        {
            "$lookup": {
                "from": "transactions",
                "localField": "wallet_address",
                "foreignField": "recipient_wallet",
                "as": "donations"
            }
        },
        {
            "$lookup": {
                "from": "users",
                "localField": "donations.donor_id",
                "foreignField": "_id",
                "as": "donors"
            }
        }
    ]
    projects = await db["projects"].aggregate(pipeline).to_list(length=None)
    if not projects:
        raise HTTPException(status_code=404, detail="No projects found for this student")
    return projects

@router.get("/donations/analytics")
async def get_donation_analytics(
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    current_admin: User = Depends(get_current_admin)
):
    db = Database.get_db()
    match_query = {}
    if start_date or end_date:
        match_query["created_at"] = {}
        if start_date:
            match_query["created_at"]["$gte"] = start_date
        if end_date:
            match_query["created_at"]["$lte"] = end_date

    pipeline = [
        {"$match": match_query},
        {
            "$lookup": {
                "from": "users",
                "localField": "donor_id",
                "foreignField": "_id",
                "as": "donor_info"
            }
        },
        {
            "$lookup": {
                "from": "projects",
                "localField": "project_id",
                "foreignField": "_id",
                "as": "project_info"
            }
        },
        {
            "$group": {
                "_id": {
                    "donor": "$donor_id",
                    "project": "$project_id"
                },
                "total_amount": {"$sum": "$amount"},
                "transactions": {"$push": "$$ROOT"},
                "donor_details": {"$first": "$donor_info"},
                "project_details": {"$first": "$project_info"}
            }
        }
    ]
    
    donations = await db["transactions"].aggregate(pipeline).to_list(length=None)
    return donations

@router.post("/verify-student/{user_id}")
async def verify_student(
    user_id: str,
    current_admin: User = Depends(get_current_admin)
):
    db = Database.get_db()
    user = await db["users"].find_one({"_id": ObjectId(user_id)})
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user["role"] != "student":
        raise HTTPException(status_code=400, detail="User is not a student")
    
    await db["users"].update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"is_verified": True}}
    )
    
    return {"message": f"Student {user['email']} has been verified"}