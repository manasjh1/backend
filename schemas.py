# backend/schemas.py
from pydantic import BaseModel, Field, validator, EmailStr # Import EmailStr
from typing import Optional, Dict, Literal # Import Literal
from datetime import datetime

# --- Base Schema (Common Farmer Fields) ---
class FarmerBaseAttrs(BaseModel):
    fullName: str = Field(..., min_length=2, max_length=100)
    aadhaarNumber: Optional[str] = Field(None, min_length=12, max_length=12, pattern=r'^\d{12}$')
    cropType: Optional[str] = Field(None, max_length=50)
    cultivationArea: Optional[str] = Field(None) # Received as string from form
    cultivationUnit: Optional[str] = Field(None, max_length=20)
    approximateProduce: Optional[str] = Field(None, max_length=100)
    pinCode: Optional[str] = Field(None, max_length=10, pattern=r'^\d{6}$')
    village: Optional[str] = Field(None, max_length=100)
    district: Optional[str] = Field(None, max_length=100)
    state: Optional[str] = Field(None, max_length=50)
    geoLocation: Optional[Dict[str, float]] = Field(None)

    @validator('*', pre=True, always=True)
    def strip_str_values(cls, v):
        if isinstance(v, str):
            return v.strip()
        return v

    # Pydantic V2 Config
    class Config:
        from_attributes = True
        populate_by_name = True

# --- Schema for Farmer Registration (Passwordless) ---
class FarmerCreate(FarmerBaseAttrs):
    mobile: str = Field(..., min_length=10, max_length=10, pattern=r'^\d{10}$')
    otp: str = Field(..., min_length=6, max_length=6, pattern=r'^\d{6}$')

# --- Schema for Farmer Login via OTP ---
class FarmerOtpLogin(BaseModel):
    mobile: str = Field(..., pattern=r'^\d{10}$')
    otp: str = Field(..., min_length=6, max_length=6, pattern=r'^\d{6}$')

# --- Schema for Farmer Profile (API Output) ---
class FarmerProfile(FarmerBaseAttrs):
    id: str
    mobile: str # Return mobile number in profile
    registered_at: datetime
    status: Optional[str] = None
    role: Optional[str] = None
    # Config inherited

# --- Schema for Admin Login (API Input) ---
class AdminLogin(BaseModel):
    email: EmailStr # Use EmailStr for validation
    password: str

# --- Schema for Admin Profile (API Output) ---
class AdminProfile(BaseModel):
    id: str # Or int if AdminUser model uses Integer ID
    email: EmailStr
    full_name: Optional[str] = None
    role: str
    created_at: datetime
    last_login_at: Optional[datetime] = None

    class Config:
        from_attributes = True

# --- Schemas for Basic OTP Operations ---
class Phone(BaseModel):
    mobile_number: str = Field(..., min_length=10, max_length=10, pattern=r'^\d{10}$')

# --- Schemas for Auth Tokens ---
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    sub: Optional[str] = None # Subject (mobile for farmer, email for admin)
    type: Optional[Literal['farmer', 'admin']] = None # User type marker

# --- Generic Success Responses ---
class SuccessResponse(BaseModel):
    Status: str
    Details: str

class RegisterSuccessResponse(BaseModel):
    success: bool
    farmer_id: str