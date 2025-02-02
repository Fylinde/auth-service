from pydantic import BaseModel
from typing import Optional

class Token(BaseModel):
    access_token: str
    token_type: str
    session_token: Optional[str] = None
    refresh_token: Optional[str] = None

class TokenRefresh(BaseModel):
    refresh_token: str
    
class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    session_token: str
    token_type: str = "bearer"
    user_id: str
    full_name: str
    email: str
    phoneNumber: str
    is_admin: bool
        
class TokenData(BaseModel):
    user_id: Optional[int] = None
    full_name: Optional[str] = None  # These fields are optional and will be fetched via user-service
    phoneNumber: Optional[str] = None
    is_admin: Optional[bool] = None
    two_factor: Optional[bool] = None
