from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Boolean
from sqlalchemy.orm import relationship
from app.database import BaseModel  # Ensure this is BaseModel now
from app.models.user import UserModel
import uuid
from datetime import datetime

class Session(BaseModel):  # Change Base to BaseModel
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, index=True)
    session_token = Column(String, unique=True, index=True, default=lambda: str(uuid.uuid4().hex))
    user_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)
    is_valid = Column(Boolean, default=True)

    user = relationship("UserModel", back_populates="sessions")
