from pydantic import BaseModel,  EmailStr
from typing import Optional

class VendorCreate(BaseModel):
    name: str
    email: EmailStr
    description: Optional[str] = None
    profile_picture: Optional[str] = None
    rating: Optional[float] = None
    password: str  # Add the password field here
    preferences: Optional[str] = None
    
class VendorResponse(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    rating: Optional[float] = None

    class Config:
        orm_mode = True

class VendorLogin(BaseModel):
    email: EmailStr
    password: str
