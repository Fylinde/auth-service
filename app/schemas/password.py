# auth-service/app/schemas/password.py

from pydantic import BaseModel, EmailStr

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordReset(BaseModel):
    token: str
    new_password: str

class PasswordChangeRequest(BaseModel):
    old_password: str
    new_password: str

class PasswordResetTokenVerification(BaseModel):
    token: str

class PasswordResetResponse(BaseModel):
    message: str

