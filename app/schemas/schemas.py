from pydantic import BaseModel, EmailStr, Field, ConfigDict, field_validator
from typing import Optional, List, Any
from datetime import datetime
from bson import ObjectId


class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v, handler):
        if not v:
            return None
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return ObjectId(v)

    @classmethod
    def __get_pydantic_json_schema__(cls, field_schema: dict[str, Any], field) -> dict[str, Any]:
        field_schema.update(type="string")
        return field_schema

    def __str__(self):
        return str(self)


class UserCreate(BaseModel):
    email: EmailStr
    username: str
    password: str
    full_name: Optional[str] = None
    wallet_address: Optional[str] = None

    model_config = ConfigDict(
        populate_by_name=True
    )


class UserResponse(BaseModel):
    id: str = Field(alias="_id")
    email: EmailStr
    username: str
    full_name: Optional[str] = None
    wallet_address: Optional[str] = None

    model_config = ConfigDict(
        populate_by_name=True,
        json_encoders={ObjectId: str}
    )


class ProjectCreate(BaseModel):
    title: str = Field(..., min_length=1)
    description: str = Field(..., min_length=10)
    objectives: str = Field(..., min_length=10)
    deliverables: str = Field(..., min_length=10)
    target_amount: float = Field(..., gt=0)
    wallet_address: str = Field(..., min_length=42, max_length=42)  # Ethereum address length
    deadline: datetime = Field(..., description="Project deadline in UTC")
    category: str = Field(..., min_length=1)
    creator_id: str = Field(..., description="ID of the user creating the project")
    tags: List[str] = Field(default_factory=list)

    model_config = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "title": "My Project",
                "description": "A detailed description of the project",
                "objectives": "Clear objectives of what the project aims to achieve",
                "deliverables": "List of tangible deliverables",
                "target_amount": 1000.0,
                "wallet_address": "0x0123456789abcdef0123456789abcdef01234567",
                "deadline": "2025-12-31T23:59:59Z",
                "category": "Education",
                "creator_id": "507f1f77bcf86cd799439011",
                "tags": ["education", "technology"]
            }
        }
    )

    @field_validator('deadline')
    def validate_deadline(cls, v: datetime) -> datetime:
        now = datetime.utcnow()
        if not isinstance(v, datetime):
            raise ValueError("Invalid datetime format")
        if v.replace(tzinfo=None) <= now:
            raise ValueError("Deadline must be in the future")
        return v


class ProjectResponse(BaseModel):
    id: str = Field(alias="_id")
    title: str
    description: str
    objectives: str
    deliverables: str
    target_amount: float
    current_amount: float = 0.0
    wallet_address: str
    deadline: datetime
    category: str
    creator_id: str
    tags: List[str] = []
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(
        populate_by_name=True,
        json_encoders={ObjectId: str}
    )


class DonationCreate(BaseModel):
    amount: float = Field(..., gt=0, description="Donation amount must be greater than 0")
    transaction_hash: str = Field(
        ..., 
        min_length=66, 
        max_length=66, 
        pattern="^0x[a-fA-F0-9]{64}$",
        description="Ethereum transaction hash"
    )
    message: Optional[str] = Field(None, max_length=500)
    project_id: str = Field(..., description="ID of the project receiving the donation")
    donor_id: str = Field(..., description="ID of the donor")

    model_config = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "amount": 100.0,
                "transaction_hash": "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "message": "Supporting your great project!",
                "project_id": "507f1f77bcf86cd799439011",
                "donor_id": "507f1f77bcf86cd799439012"
            }
        }
    )

    @field_validator('amount')
    def validate_amount(cls, v):
        if v <= 0:
            raise ValueError("Amount must be greater than 0")
        return v


class DonationResponse(BaseModel):
    id: str = Field(alias="_id")
    amount: float
    transaction_hash: str
    message: Optional[str] = None
    donor_id: str
    project_id: str
    status: str = Field(default="pending")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    confirmed_at: Optional[datetime] = None

    model_config = ConfigDict(
        populate_by_name=True,
        json_encoders={ObjectId: str},
        json_schema_extra={
            "example": {
                "id": "507f1f77bcf86cd799439013",
                "amount": 100.0,
                "transaction_hash": "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "message": "Supporting your great project!",
                "donor_id": "507f1f77bcf86cd799439012",
                "project_id": "507f1f77bcf86cd799439011",
                "status": "pending",
                "created_at": "2025-05-09T00:00:00Z",
                "confirmed_at": None
            }
        }
    )


class SignUpRequest(BaseModel):
    email: EmailStr
    username: str
    password: str
    full_name: Optional[str] = None
    wallet_address: Optional[str] = None
    role: str = Field(..., enum=["admin", "donor", "student"])

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "user@example.com",
                "username": "testuser",
                "password": "strongpassword123",
                "full_name": "Test User",
                "wallet_address": "0x0123456789abcdef0123456789abcdef01234567",
                "role": "donor"
            }
        }
    )


class LoginRequest(BaseModel):
    email: EmailStr
    password: str

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "user@example.com",
                "password": "strongpassword123"
            }
        }
    )


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer"
            }
        }
    )

class RegisterUser(BaseModel):
    first_name: str
    last_name: str
    username: str
    email: EmailStr
    school: str
    expected_graduation_year: int = Field(..., ge=2025)
    stellar_wallet: Optional[str] = None
    password: str
    confirm_password: str

class RegisterDonor(BaseModel):
    first_name: str
    last_name: str
    username: str
    email: EmailStr
    organization: Optional[str] = None
    preferred_categories: Optional[List[str]] = Field(default_factory=list)
    stellar_wallet: Optional[str] = None
    password: str
    confirm_password: str

class StudentProfile(BaseModel):
    institution: str
    student_id: str
    field_of_study: str
    year_of_study: int
    is_verified: bool = False
    school: str
    expected_graduation_year: int = Field(..., ge=2025)

class DonorProfile(BaseModel):
    organization: Optional[str] = None
    preferred_categories: List[str] = Field(default_factory=list)
    donation_history: List[str] = Field(default_factory=list)
    total_donated: float = 0.0

class User(BaseModel):
    id: Optional[str]
    email: EmailStr
    username: str
    first_name: str
    last_name: str
    full_name: Optional[str] = None
    stellar_wallet: Optional[str] = None
    role: str
    student_profile: Optional[StudentProfile] = None
    donor_profile: Optional[DonorProfile] = None
    created_at: Optional[str]
    updated_at: Optional[str]