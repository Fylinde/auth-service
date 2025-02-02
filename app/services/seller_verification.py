# In auth_service.py or a relevant service file in auth-service
from datetime import datetime
from app.models.verification_code import VerificationCodeModel  # This is an example; use your actual model for verification codes
from sqlalchemy.orm import Session
from app.config import settings
import requests
from typing import Tuple, Optional
import logging
from app.schemas.otp_schemas import SellerVerificationStatusUpdate
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_exception_type


VENDOR_SERVICE_URL = settings.VENDOR_SERVICE_URL

# def verify_seller_code(db: Session, code: str, email: str) -> Tuple[bool, Optional[int]]:
#     # Query the verification code based on email and code
#     verification_record = db.query(VerificationCodeModel).filter(
#         VerificationCodeModel.email == email,
#         VerificationCodeModel.code == code,
#         VerificationCodeModel.expires_at > datetime.utcnow()
#     ).first()

#     # If the code exists and is not expired, mark it as verified
#     if verification_record:
#         sellerId = verification_record.sellerId  # Get the associated seller ID
#         # Optionally mark the code as used or delete it
#         db.delete(verification_record)
#         db.commit()
#         return True, sellerId  # Return True and the sellerId if verification is successful

#     return False, None  # Return False and None if verification fails

def verify_seller_code(db: Session, code: Optional[str] = None, email: Optional[str] = None, sellerId: Optional[str] = None) -> Tuple[bool, Optional[str]]:
    """
    Verifies the seller's verification code against the database record.
    """
    try:
        logging.info(f"[Backend] Starting verification for email: {email}, code: {code}, sellerId: {sellerId}")

        # Determine the query criteria
        query_filter = []
        if code:
            query_filter.append(VerificationCodeModel.code == code)
        if email:
            query_filter.append(VerificationCodeModel.email == email)
        if sellerId:
            query_filter.append(VerificationCodeModel.sellerId == sellerId)

        # Debug SQL Query
        logging.info(f"[Backend] Querying verification_codes table with: {query_filter}")

        # Query the database for the verification code
        verification_record = db.query(VerificationCodeModel).filter(*query_filter).first()

        if not verification_record:
            logging.warning("[Backend] No matching verification code found in database.")
            return False, None

        logging.info(f"[Backend] Found verification record: {verification_record}")

        # Check if the code is expired
        if verification_record.is_expired():
            logging.warning(f"[Backend] Verification code expired at {verification_record.expires_at}. Current time: {datetime.utcnow()}")
            return False, None

        logging.info(f"[Backend] Verification successful for seller ID: {verification_record.sellerId}")
        return True, verification_record.sellerId

    except Exception as e:
        logging.error(f"[Backend] Error verifying seller code: {str(e)}")
        return False, None





@retry(
    stop=stop_after_attempt(3),  # Retry up to 3 times
    wait=wait_fixed(2),  # Wait 2 seconds between retries
    retry=retry_if_exception_type(requests.exceptions.RequestException),
)
# def notify_seller_service(sellerId: int, is_email: bool = True):
#     """
#     Notify vendor-service to update the seller's email verification status.
#     Includes retry logic for resilience.
#     """
#     payload = SellerVerificationStatusUpdate(sellerId=sellerId, is_email=is_email).dict()
#     logging.info(f"Sending payload to vendor-service /update_verification_status: {payload}")

#     try:
#         response = requests.post(
#             f"{VENDOR_SERVICE_URL}/sellers/update_verification_status",
#             json=payload,
#             timeout=10  # 10 seconds timeout for the request
#         )
#         response.raise_for_status()  # Raise exception for 4xx/5xx responses
#         logging.info(f"Successfully notified vendor-service for sellerId: {sellerId}")
#     except requests.exceptions.Timeout:
#         logging.error(f"Timeout occurred while notifying vendor-service for sellerId: {sellerId}")
#         raise
#     except requests.exceptions.RequestException as e:
#         logging.error(f"Failed to notify vendor-service for sellerId {sellerId}: {e}")
#         raise


def notify_seller_service(sellerId: int, is_email: bool = True):
    """
    Notifies the vendor-service about the verification status of the seller.
    
    Parameters:
    - sellerId (int): The ID of the seller.
    - is_email (bool): Whether the verification was via email (True) or SMS (False).
    
    Returns:
    - dict: Success or failure message.
    """
    try:
        logging.info(f"Notifying vendor service for sellerId: {sellerId}, is_email: {is_email}")
        
        # Prepare the payload
        payload = SellerVerificationStatusUpdate(sellerId=sellerId, is_email=is_email)
        
        # Define the vendor service URL
        vendor_service_url = f"{VENDOR_SERVICE_URL}/sellers/update_verification_status"
        
        # Send a request to the vendor service
        response = requests.post(vendor_service_url, json=payload.dict())
        response.raise_for_status()  # Raise exception for HTTP errors
        
        logging.info(f"Vendor service notified successfully for sellerId: {sellerId}")
        return {"message": "Vendor service notified successfully."}
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to notify vendor service: {str(e)}")
        return {"error": "Failed to notify vendor service.", "details": str(e)}