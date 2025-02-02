from sqlalchemy import Column, Integer, String,  DateTime, Boolean
from app.database import BaseModel  # Ensure this is BaseModel now
import uuid
from datetime import datetime

class SessionModel(BaseModel):  # Change Base to BaseModel
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, index=True)
    session_token = Column(String, unique=True, index=True, default=lambda: str(uuid.uuid4().hex))
    user_id = Column(String, nullable=False, index=True)
    sellerId = Column(String, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)
    is_valid = Column(Boolean, default=True)

   
