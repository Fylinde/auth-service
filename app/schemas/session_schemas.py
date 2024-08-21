from pydantic import BaseModel
from datetime import datetime

class SessionCreate(BaseModel):
    user_id: int
    session_token: str
    expires_at: datetime
    is_valid: bool

class SessionResponse(BaseModel):
    id: int
    user_id: int
    session_token: str
    created_at: datetime
    expires_at: datetime

    class Config:
        orm_mode = True
        