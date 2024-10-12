from pydantic import BaseModel

class LogoutRequest(BaseModel):
    session_token: str  # Rename to session_token for clarity
    
class LogoutResponse(BaseModel):
    message: str
