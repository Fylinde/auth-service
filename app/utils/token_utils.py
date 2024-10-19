import secrets
import random
import string
from app.security import oauth2_scheme
from app.config import settings
import os
from fastapi import HTTPException, Depends
from jose import jwt, JWTError
from app.crud.user_crud import create_otp_record
from app.models.otp import OTPModel
from sqlalchemy.orm import Session
from datetime import datetime

SECRET_KEY = os.getenv("SECRET_KEY", settings.SECRET_KEY)
ALGORITHM = os.getenv("ALGORITHM", settings.ALGORITHM)
ACCESS_TOKEN_EXPIRE_MINUTES = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", settings.ACCESS_TOKEN_EXPIRE_MINUTES)
USER_SERVICE_URL = os.getenv("USER_SERVICE_URL", settings.USER_SERVICE_URL)

def create_session_token() -> str:
    """
    Generate a random session token.
    """
    return secrets.token_hex(16)

def generate_verification_code(length=6):
    """
    Generate a random numeric verification code.
    """
    digits = string.digits
    return ''.join(random.choices(digits, k=length))

def generate_otp(length=6):
    """
    Generate a random numeric OTP.
    """
    return ''.join(random.choices(string.digits, k=length))

def get_user_id_from_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("user_id")
        if user_id is None:
            raise HTTPException(status_code=401, detail="User ID not found in token")
        return user_id
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    
    
def generate_and_store_otp(db, user_id: str):
    # Generate the OTP
    otp_code = generate_otp()
    
    # Store the OTP in the database or cache, linked to the user_id
    create_otp_record(db, user_id, otp_code)
    
    return otp_code

def save_otp_to_database(db: Session, user_id: str, otp_code: str, validity_duration: int = 300):
    """
    Save the OTP to the database.
    
    :param db: Database session.
    :param user_id: The identifier for the user associated with this OTP.
    :param otp_code: The OTP code to be stored.
    :param validity_duration: Duration in seconds for OTP validity.
    :return: The newly created OTP entry.
    """
    # Create an OTP entry instance
    otp_entry = OTPModel(
        user_id=user_id,
        otp_code=otp_code,
        created_at=datetime.utcnow()
    )
    
    # Add and commit the new OTP entry to the database
    db.add(otp_entry)
    db.commit()
    db.refresh(otp_entry)  # Refresh to get any updated data like generated ID
    
    return otp_entry  # Optionally return the OTP entry