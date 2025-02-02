# auth-service/app/crud/user_crud.py

import requests
from fastapi import HTTPException
import logging
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from app.models.otp import OTPModel  # This model is specifically for temporary OTP storage
from app.config import settings
import os




logger = logging.getLogger(__name__)

OTP_VALIDITY_DURATION = os.getenv("OTP_VALIDITY_DURATION", settings.OTP_VALIDITY_DURATION)
USER_SERVICE_URL = "http://user-service:8001/users"

def verify_user_code(code: str):
    """
    Sends the verification code to user-service to verify the user's email.
    """
    try:
        logging.info(f"Sending verification request to {USER_SERVICE_URL}/verify-code with code: {code}")

        response = requests.get(f"{USER_SERVICE_URL}/verify-code", params={"code": code})

        logging.info(f"Received response status: {response.status_code}, body: {response.text}")

        if response.status_code != 200:
            raise HTTPException(status_code=400, detail="Invalid or expired verification code.")

        # Log the successful verification details and return the response
        verification_data = response.json()
        logging.info(f"Verification successful: {verification_data}")
        return verification_data

    except requests.exceptions.RequestException as e:
        logging.error(f"Error during request to user-service: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to verify code: {str(e)}")

def create_otp_record(db: Session, user_id: str, otp_code: str):
    # Store the OTP with an expiration time
    otp_entry = OTPModel(
        user_id=user_id,
        otp_code=otp_code,
        created_at=datetime.utcnow()
    )
    db.add(otp_entry)
    db.commit()
    return otp_entry

def get_otp_record(db: Session, user_id: str):
    # Retrieve the OTP record by user_id
    return db.query(OTPModel).filter(OTPModel.user_id == user_id).first()

def verify_and_delete_otp(db: Session, user_id: str, otp_code: str):
    # Verify the OTP code and delete it if valid
    otp_entry = db.query(OTPModel).filter(OTPModel.user_id == user_id, OTPModel.otp_code == otp_code).first()
    if otp_entry:
        # Check if the OTP is still valid
        if datetime.utcnow() - otp_entry.created_at > timedelta(seconds=OTP_VALIDITY_DURATION):
            raise ValueError("OTP has expired")
        
        # Delete the OTP after verification
        db.delete(otp_entry)
        db.commit()
        return True
    return False

