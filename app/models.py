from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime

class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    confirm_password: str = Field(..., min_length=8)

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class OTPVerify(BaseModel):
    email: EmailStr
    otp_code: str
    purpose: str

class OTPRequest(BaseModel):
    email: EmailStr
    purpose: str

class Token(BaseModel):
    access_token: str
    token_type: str
    is_verified: bool

class UserResponse(BaseModel):
    id: int
    email: str
    is_verified: bool
    created_at: datetime