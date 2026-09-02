from pydantic import BaseModel, EmailStr, Field, validator
from typing import Literal, Optional
from datetime import datetime

class RegistrationRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    confirm_password: str = Field(..., min_length=8)
    
    @validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'password' in values and v != values['password']:
            raise ValueError('Passwords do not match')
        return v

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class OTPRequest(BaseModel):
    email: EmailStr
    purpose: Literal['registration', 'login']

class OTPVerifyRequest(BaseModel):
    email: EmailStr
    otp_code: str = Field(..., min_length=6, max_length=6)
    purpose: Literal['registration', 'login']

# NEW: Refresh token request
class RefreshTokenRequest(BaseModel):
    refresh_token: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    email: str
    is_verified: bool

class MessageResponse(BaseModel):
    message: str
    success: bool
    data: Optional[dict] = None

class UserVerificationStatus(BaseModel):
    email: str
    is_verified: bool
    status: str