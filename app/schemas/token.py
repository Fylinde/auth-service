# auth-service/app/schemas/token.py

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
    token_type: str
    refresh_token: str
