# services.py
import requests
from datetime import timedelta, datetime
from jose import  jwt
from fastapi import HTTPException
from sqlalchemy.orm import Session
from app.config import settings
import os
from app.models.otp import OTPModel
import logging

logger = logging.getLogger(__name__)

REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 7))
SECRET_KEY = os.getenv("SECRET_KEY", settings.SECRET_KEY)
OTP_VALIDITY_DURATION = os.getenv("OTP_VALIDITY_DURATION", settings.OTP_VALIDITY_DURATION)
ALGORITHM = os.getenv("ALGORITHM", settings.ALGORITHM)
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 15))  # Default to 15 minutes if not set
USER_SERVICE_URL = os.getenv("USER_SERVICE_URL", settings.USER_SERVICE_URL)

def get_user_from_user_service(identifier: str, password: str):
    response = requests.post(f"{USER_SERVICE_URL}/verify_user", data={"identifier": identifier, "password": password})
    
    if response.status_code != 200:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return response.json()

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_user_credentials(username: str, password: str):
    # Make a request to user-service to authenticate user credentials
    response = requests.post(
        f"{USER_SERVICE_URL}/authenticate",
        json={"username": username, "password": password}
    )
    
    if response.status_code != 200:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # Assuming the user data includes contact information for sending OTP
    return response.json()

    
def get_user_data(user_id: str):
    response = requests.get(f"{USER_SERVICE_URL}/{user_id}")
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail="Failed to retrieve user data")
    return response.json()

def get_user_by_contact(contact: str):
    # This might be an email or phone number depending on the input
    response = requests.get(f"{USER_SERVICE_URL}/get-by-contact?contact={contact}")
    if response.status_code != 200:
        raise HTTPException(status_code=404, detail="User not found")
    return response.json()

def enable_user_2fa(user_id: str, code: str):
    response = requests.post(f"{USER_SERVICE_URL}/{user_id}/enable-2fa", json={"code": code})
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail="Failed to enable 2FA")
    return response.json()

def disable_user_2fa(user_id: str):
    response = requests.post(f"{USER_SERVICE_URL}/{user_id}/disable-2fa")
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail="Failed to disable 2FA")
    return response.json()

# services.py (continued)
# services.py in auth-service

def verify_otp_code(db: Session, user_id: str, otp: str) -> bool:
    # Fetch the OTP record from the database
    otp_record = db.query(OTPModel).filter(
        OTPModel.user_id == user_id,
        OTPModel.otp_code == otp
    ).first()

    # Log details for debugging
    if not otp_record:
        logger.warning(f"OTP not found or already used for user_id: {user_id}")
        return False

    # Check if OTP is expired
    if otp_record.is_expired(OTP_VALIDITY_DURATION):
        logger.warning(f"OTP expired for user_id: {user_id}")
        return False

    # OTP is valid, so proceed with deletion or marking it as used
    db.delete(otp_record)
    db.commit()
    logger.info(f"OTP verified successfully for user_id: {user_id}")
    return True
