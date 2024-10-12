# models.py

import uuid
from sqlalchemy import Column, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

BaseModel = declarative_base()

class OTPModel(BaseModel):
    __tablename__ = "otp_codes"
    
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, nullable=False, index=True)  # User identifier
    otp_code = Column(String, nullable=False)  # The OTP code itself
    created_at = Column(DateTime, default=datetime.utcnow)  # Timestamp when OTP was created

    def is_expired(self, validity_duration: int) -> bool:
        """Check if the OTP has expired based on validity_duration in seconds."""
        return (datetime.utcnow() - self.created_at).total_seconds() > validity_duration
