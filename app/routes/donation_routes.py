from fastapi import APIRouter, HTTPException
from ..models.models import Transaction
from ..schemas.schemas import DonationCreate
from ..core.database import Database

router = APIRouter()

@router.post("/", response_model=Transaction)
async def create_donation(donation: DonationCreate):
    db = Database.get_db()
    donation_dict = donation.dict()
    result = await db.donations.insert_one(donation_dict)
    created_donation = await db.donations.find_one({"_id": result.inserted_id})
    return created_donation

@router.get("/{donation_id}")
async def get_donation(donation_id: str):
    db = Database.get_db()
    if (donation := await db.donations.find_one({"_id": donation_id})) is not None:
        return donation
    raise HTTPException(status_code=404, detail="Donation not found")