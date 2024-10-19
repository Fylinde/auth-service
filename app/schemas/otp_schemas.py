from pydantic import BaseModel, Field
from datetime import datetime

class OTPSchema(BaseModel):
    otp_code: str = Field(..., description="The OTP code sent to the user")
    expires_at: datetime = Field(..., description="The timestamp when the OTP will expire")
    contact_method: str = Field(..., description="The method used to send the OTP, e.g., 'email' or 'sms'")
    user_id: int = Field(..., description="The user ID associated with this OTP")


class OTPResponse(BaseModel):
    otp_code: str = Field(..., description="The OTP code sent to the user")
    expires_at: datetime = Field(..., description="When the OTP expires")

class TokenResponse(BaseModel):
    access_token: str = Field(..., description="The access token for the session")
    refresh_token: str = Field(..., description="The refresh token for renewing the session")
    token_type: str = Field(..., description="The type of token, usually 'bearer'")

