from sqlalchemy import Column, Integer, String, Boolean, DateTime, ARRAY
from sqlalchemy.orm import relationship
from passlib.context import CryptContext
from app.database import BaseModel  # Change to BaseModel
import pyotp

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class UserModel(BaseModel):  # Change Base to BaseModel
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    role = Column(String, default="customer")  # Default role as "customer"
    two_factor_enabled = Column(Boolean, default=False)
    two_factor_secret = Column(String)
    password_last_updated = Column(DateTime)
    failed_login_attempts = Column(Integer, default=0)
    account_locked = Column(Boolean, default=False)
    backup_codes = Column(ARRAY(String))

    sessions = relationship("Session", back_populates="user")  # Define relationship with sessions

    def verify_password(self, password: str) -> bool:
        return pwd_context.verify(password, self.hashed_password)

    def generate_2fa_code(self) -> str:
        if not self.two_factor_secret:
            self.two_factor_secret = pyotp.random_base32()
        totp = pyotp.TOTP(self.two_factor_secret)
        return totp.now()

    def verify_2fa_code(self, code: str) -> bool:
        if not self.two_factor_secret:
            return False
        totp = pyotp.TOTP(self.two_factor_secret)
        return totp.verify(code)
