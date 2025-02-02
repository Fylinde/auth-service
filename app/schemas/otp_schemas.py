from pydantic import BaseModel, Field, EmailStr, field_validator
from datetime import datetime


VALID_SELLER_TYPES = {"individual", "professional"}

# Validate 'seller_type'
def validate_seller_type(value: str) -> str:
    value = value.strip().lower()
    if value not in VALID_SELLER_TYPES:
        raise ValueError(f"Invalid seller type: {value}. Must be one of {VALID_SELLER_TYPES}")
    return value

class OTPSchema(BaseModel):
    otp_code: str = Field(..., description="The OTP code sent to the user")
    expires_at: datetime = Field(..., description="The timestamp when the OTP will expire")
    contact_method: str = Field(..., description="The method used to send the OTP, e.g., 'email' or 'sms'")
    user_id: str = Field(..., description="The user ID associated with this OTP")


class OTPResponse(BaseModel):
    otp_code: str = Field(..., description="The OTP code sent to the user")
    expires_at: datetime = Field(..., description="When the OTP expires")

class TokenResponse(BaseModel):
    access_token: str = Field(..., description="The access token for the session")
    refresh_token: str = Field(..., description="The refresh token for renewing the session")
    token_type: str = Field(..., description="The type of token, usually 'bearer'")

class VerificationPayload(BaseModel):
    sellerId: str
    contact: str
    is_email: bool = Field(default=True, example=True)
    seller_type: str = Field(..., example="individual")  # New field for seller type

    @field_validator("seller_type", mode="before")
    def validate_seller_type(cls, value: str) -> str:
        return validate_seller_type(value)

class VerifyCodeRequest(BaseModel):
    code: str
    email: EmailStr  # This ensures `email` is a valid email format

class SellerVerificationStatusUpdate(BaseModel):
    sellerId: str
    is_email: bool = True
