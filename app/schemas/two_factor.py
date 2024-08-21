# auth-service/app/schemas/2fa.py

from pydantic import BaseModel
from typing import Optional
from .user_schemas import UserLogin

class Enable2FARequest(BaseModel):
    code: str

class Disable2FARequest(BaseModel):
    code: str

class UserLoginWith2FA(UserLogin):
    code: Optional[str] = None

class Generate2FACodeResponse(BaseModel):
    current_code: str

class Verify2FARequest(BaseModel):
    code: str

class Message(BaseModel):
    message: str
    
class TwoFactorVerifyRequest(BaseModel):
    code: str  
    
class TwoFactorEnableRequest(BaseModel):
    code: str    