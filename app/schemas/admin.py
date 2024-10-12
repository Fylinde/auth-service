from pydantic import BaseModel, EmailStr

class AdminLogin(BaseModel):
    email: str
    password: str
class LockAccountRequest(BaseModel):
    email: EmailStr
    
class UnlockAccountRequest(BaseModel):
    email: EmailStr       
    
class RoleUpdate(BaseModel):
    full_name: str
    role: str    
    
class AdminCreate(BaseModel):
    full_name: str
    email: str
    password: str
    secret_key: str  # Add secret_key to the body    