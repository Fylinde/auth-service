from pydantic import BaseModel, EmailStr,Field, field_validator, FieldValidationInfo
from typing import Optional
from datetime import datetime

class UserLogin(BaseModel):
    email: Optional[EmailStr] = None
    phone_number: Optional[str] = None
    password: str

    @field_validator("phone_number", "email", mode="before")
    def validate_email_or_phone(cls, value, info: FieldValidationInfo):
        email = info.data.get("email")
        phone_number = info.data.get("phone_number")
        
        if not email and not phone_number:
            raise ValueError("Either 'email' or 'phone_number' must be provided.")
        if email and phone_number:
            raise ValueError("Provide only one of 'email' or 'phone_number', not both.")
        
        return value
    
class VendorLogin(BaseModel):
    email: str
    password: str

class TwoFactorVerifyRequest(BaseModel):
    user_id: int
    code: str

class SessionCreate(BaseModel):
    user_id: int
    session_token: str
    expires_at: datetime
    is_valid: bool

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    refresh_token: Optional[str] = None
    session_token: Optional[str] = None
    user: Optional[dict] = None

    class Config:
        from_attributes = True

class EmailVerificationRequest(BaseModel):
    code: str

class EmailVerificationResponse(BaseModel):
    id: int
    full_name: str
    email: str
    is_admin: bool
    access_token: str
    refresh_token: str
    access_token_expiration: Optional[datetime] = None
    refresh_token_expiration: Optional[datetime] = None

    class Config:
        from_attributes = True
        
        
class UserRegistrationRequest(BaseModel):
    full_name: str = Field(..., example="John Doe")
    email: EmailStr = Field(..., example="johndoe@example.com")
    password: str = Field(..., min_length=6, example="strongpassword")
    phone_number: Optional[str] = Field(None, example="1234567890")
    
    # Fields to be added by the service logic (not required from the user input directly)
    verification_code: Optional[str] = Field(None, example="verification-code")
    verification_expiration: Optional[str] = Field(None, example="2024-12-31T23:59:59")
    profile_picture: Optional[str] = Field(None, example="http://example.com/profile.jpg")
    preferences: Optional[dict] = Field(default_factory=dict, example={"notifications": True})
    is_email_verified: Optional[bool] = Field(default=False)
    is_phone_verified: Optional[bool] = Field(default=False)

class VendorRegistrationRequest(BaseModel):
    name: str = Field(..., example="Best Vendor")
    email: EmailStr = Field(..., example="vendor@example.com")
    password: str = Field(..., min_length=6, example="vendorpassword")
    phone_number: Optional[str] = Field(None, example="0987654321")
    description: Optional[str] = Field(None, example="Description of the vendor's business.")

class RegistrationResponse(BaseModel):
    id: Optional[int] = None  # Make id optional to allow None values
    full_name: Optional[str] = None  # Make fields optional if they are not needed pre-verification
    email: str
    phone_number: Optional[str] = None
    message: str
    name: Optional[str] = None  # Add name as optional if necessary

    class Config:
        from_attributes = True