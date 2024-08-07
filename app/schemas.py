from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

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

class Token(BaseModel):
    access_token: str
    token_type: str
    session_token: str
    refresh_token: Optional[str] = None

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    refresh_token: str

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordReset(BaseModel):
    token: str
    new_password: str

class TokenRefresh(BaseModel):
    refresh_token: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: EmailStr
    role: str
    is_active: bool

    class Config:
        from_attributes = True
        
class Enable2FARequest(BaseModel):
    code: str

class Disable2FARequest(BaseModel):
    code: str

class UserLoginWith2FA(UserLogin):
    code: Optional[str] = None

class RoleUpdate(BaseModel):
    username: str
    role: str
    
class Enable2FASchema(BaseModel):
    code: str
    
class Message(BaseModel):
    message: str    

class SessionResponse(BaseModel):
    id: int
    user_id: int
    session_token: str
    created_at: datetime
    expires_at: datetime

    class Config:
        orm_mode = True    

class LockAccountRequest(BaseModel):
    email: EmailStr
    
class UnlockAccountRequest(BaseModel):
    email: EmailStr    