from pydantic import BaseModel, EmailStr
from typing import Optional

class Enable2FARequest(BaseModel):
    code: str

class Disable2FARequest(BaseModel):
    code: str

class UserLoginWith2FA(BaseModel):
    email: str
    password: str
    code: Optional[str] = None

class Generate2FACodeResponse(BaseModel):
    current_code: str

class Verify2FARequest(BaseModel):
    code: str

class MessageResponse(BaseModel):
    message: str
    
class TwoFactorVerifyRequest(BaseModel):
    code: str  
    
class TwoFactorEnableRequest(BaseModel):
    code: str

class OTPRequest(BaseModel):
    email: Optional[EmailStr] = None
    phone_number: Optional[str] = None
    carrier_gateway: Optional[str] = None

class OTPVerifyRequest(BaseModel):
    contact: str
    otp: str

class OTPResponse(BaseModel):
    code: str  # For generated OTP if needed in the response