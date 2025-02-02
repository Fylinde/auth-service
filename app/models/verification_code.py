# app/models.py or a similar models file

from sqlalchemy import Column, Integer, String, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

BaseModel = declarative_base()

class VerificationCodeModel(BaseModel):
    __tablename__ = "verification_codes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String, nullable=True)  # Email field
    phoneNumber = Column(String, nullable=True)  # Phone number field
    code = Column(String, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    is_email = Column(Boolean, nullable=False)
    sellerId = Column(String, nullable=False, index=True)

    
    def is_expired(self) -> bool:
        """Check if the verification code has expired."""
        return datetime.utcnow() > self.expires_at
