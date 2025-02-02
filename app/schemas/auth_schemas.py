from pydantic import BaseModel, EmailStr,Field, field_validator, FieldValidationInfo
from typing import Optional
from datetime import datetime

VALID_SELLER_TYPES = {"individual", "professional"}  # Define valid seller types


# Validate 'seller_type'
def validate_seller_type(value: str) -> str:
    value = value.strip().lower()
    if value not in VALID_SELLER_TYPES:
        raise ValueError(f"Invalid seller type: {value}. Must be one of {VALID_SELLER_TYPES}")
    return value

class UserLogin(BaseModel):
    email: Optional[EmailStr] = None
    phoneNumber: Optional[str] = None
    password: str

    @field_validator("phoneNumber", "email", mode="before")
    def validate_email_or_phone(cls, value, info: FieldValidationInfo):
        email = info.data.get("email")
        phoneNumber = info.data.get("phoneNumber")
        
        if not email and not phoneNumber:
            raise ValueError("Either 'email' or 'phoneNumber' must be provided.")
        if email and phoneNumber:
            raise ValueError("Provide only one of 'email' or 'phoneNumber', not both.")
        
        return value
    
class SellerLogin(BaseModel):
    email: str
    password: str

class TwoFactorVerifyRequest(BaseModel):
    user_id: str
    code: str

class SessionCreate(BaseModel):
    user_id: str
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
    phoneNumber: Optional[str] = Field(None, example="1234567890")
    
    # Fields to be added by the service logic (not required from the user input directly)
    verification_code: Optional[str] = Field(None, example="verification-code")
    verification_expiration: Optional[str] = Field(None, example="2024-12-31T23:59:59")
    profile_picture: Optional[str] = Field(None, example="http://example.com/profile.jpg")
    preferences: Optional[dict] = Field(default_factory=dict, example={"notifications": True})
    is_email_verified: Optional[bool] = Field(default=False)
    is_phone_verified: Optional[bool] = Field(default=False)

class SellerRegistrationRequest(BaseModel):
    full_name: str = Field(..., example="John Doe")
    email: EmailStr = Field(..., example="johndoe@example.com")
    password: str = Field(..., min_length=6, example="securepassword")
    phoneNumber: Optional[str] = Field(None, example="1234567890")
    seller_type: str = Field(..., example="individual")  # New field for seller type

    @field_validator("seller_type", mode="before")
    def validate_seller_type(cls, value: str) -> str:
        return validate_seller_type(value)



class SellerVerificationRequest(BaseModel):
    sellerId: str
    contact: str
    is_email: bool = Field(default=True, example=True)
    seller_type: str = Field(..., example="individual")  # New field for seller type

    @field_validator("seller_type", mode="before")
    def validate_seller_type(cls, value: str) -> str:
        return validate_seller_type(value)

class RegistrationResponse(BaseModel):
    id: Optional[int] = None
    full_name: Optional[str] = None
    email: str
    phoneNumber: Optional[str] = None
    message: str
    seller_type: Optional[str] = None  # Include seller type in response if needed

    class Config:
        from_attributes = True

class EmailVerificationRequest(BaseModel):
    code: str
    seller_type: str = Field(..., example="professional")  # Add seller type to the request

    @field_validator("seller_type", mode="before")
    def validate_seller_type(cls, value: str) -> str:
        return validate_seller_type(value)    
    
