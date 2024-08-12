from pydantic import BaseModel, EmailStr

class AdminLogin(BaseModel):
    email: str
    password: str
class LockAccountRequest(BaseModel):
    email: EmailStr
    
class UnlockAccountRequest(BaseModel):
    email: EmailStr       
    
class RoleUpdate(BaseModel):
    username: str
    role: str    
    
class AdminCreate(BaseModel):
    username: str
    email: str
    password: str
    secret_key: str  # Add secret_key to the body    