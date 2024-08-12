from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    profile_picture: Optional[str] = None
    preferences: Optional[str] = None
    
class UserResponse(BaseModel):
    id: int
    username: str
    email: EmailStr
    is_active: bool
    role: str
    two_factor_enabled: bool
    failed_login_attempts: int
    account_locked: bool
    profile_picture: Optional[str] = None
    preferences: Optional[str] = None

    class Config:
        orm_mode = True

class UserUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    password: Optional[str] = None
    role: Optional[str] = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str