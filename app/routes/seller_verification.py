from fastapi import APIRouter, HTTPException, Depends, Body
from datetime import timedelta, datetime
from sqlalchemy.orm import Session
import logging
from fastapi import Request
import requests
import os
from app.database import get_db
from app.config import settings
from app.utils.store_verification_code import store_verification_code
from app.services.seller_verification import verify_seller_code, notify_seller_service
from app.schemas.otp_schemas import VerificationPayload
from app.utils.verification_service import send_verification
from app.utils.token_utils import generate_verification_code
from app.models.verification_code import VerificationCodeModel
import traceback
from sqlalchemy.exc import OperationalError

SECRET_KEY = os.getenv("SECRET_KEY", settings.SECRET_KEY)
OTP_VALIDITY_DURATION = int(os.getenv("OTP_VALIDITY_DURATION", "300"))
VENDOR_SERVICE_URL = os.getenv("VENDOR_SERVICE_URL", settings.VENDOR_SERVICE_URL)
BASE_URL = os.getenv("BASE_URL", "http://localhost:3000")  # Default to localhost for dev


router = APIRouter()

@router.post("/generate-verification-code")
async def generate_and_send_verification_code(payload: VerificationPayload = Body(...), db: Session = Depends(get_db)):
    """
    Generates or retrieves a verification code for a seller and sends it via email/SMS.
    """

    try:
        logging.info(f"📩 Received request: {payload.dict()}")

        contact = payload.contact
        is_email = payload.is_email
        sellerId = payload.sellerId
        seller_type = payload.seller_type

        # ✅ Step 1: Validate Inputs
        if not isinstance(sellerId, str):
            logging.error(f"❌ Invalid sellerId format: {sellerId}")
            raise HTTPException(status_code=400, detail="Invalid sellerId. Must be a string.")
        
        if not contact:
            logging.error("❌ Missing contact information (email or phone).")
            raise HTTPException(status_code=400, detail="Contact is required.")

        logging.info(f"🔎 Checking if existing verification code exists for seller {sellerId}")

        # ✅ Step 2: Check for Existing Code (Retry on DB Failure)
        retry_count = 0
        while retry_count < 3:
            try:
                existing_code = db.query(VerificationCodeModel).filter(
                    VerificationCodeModel.sellerId == sellerId,
                    VerificationCodeModel.is_email == is_email,
                    VerificationCodeModel.expires_at > datetime.utcnow()
                ).first()
                break  # ✅ Success, exit retry loop
            except OperationalError as db_error:
                retry_count += 1
                logging.warning(f"⚠️ Database error (Attempt {retry_count}/3): {db_error}")
                if retry_count == 3:
                    logging.critical("🚨 Database connection failed after 3 attempts.")
                    raise HTTPException(status_code=500, detail="Database connection issue. Please try again.")

        # ✅ Step 3: Use Existing Code or Generate a New One
        if existing_code:
            verification_code = existing_code.code
            logging.info(f"🔄 Reusing existing verification code: {verification_code}")
        else:
            verification_code = generate_verification_code()
            expiration_time = datetime.utcnow() + timedelta(seconds=OTP_VALIDITY_DURATION)
            logging.info(f"🆕 Generated new verification code: {verification_code}")

            # ✅ Step 4: Store the New Code in the Database
            try:
                store_verification_code(
                    db=db,
                    code=verification_code,
                    expiration=expiration_time,
                    is_email=is_email,
                    email=contact if is_email else None,
                    phoneNumber=contact if not is_email else None,
                    sellerId=sellerId
                )
                logging.info("✅ New verification code stored successfully.")
            except OperationalError as db_error:
                logging.error(f"❌ Database error while storing verification code: {db_error}")
                raise HTTPException(status_code=500, detail="Database error while storing verification code.")

        # ✅ Step 5: Send Verification Code
        logging.info(f"📤 Sending verification code to {contact}")
        sent_successfully = send_verification(contact, verification_code, seller_type, is_email)

        if not sent_successfully:
            logging.error(f"❌ Failed to send verification code to {contact}")
            raise HTTPException(status_code=500, detail="Failed to send verification code")

        logging.info(f"✅ Verification code {verification_code} sent successfully to {contact}")
        
        return {"message": "Verification code sent successfully", "verification_code": verification_code}

    except HTTPException as e:
        logging.error(f"🚨 HTTP Exception: {e.detail}")
        raise e
    except Exception as e:
        logging.error(f"❌ Unexpected error in verification: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to generate verification code")

# @router.post("/generate-verification-code")
# def generate_and_send_verification_code(
#     payload: VerificationPayload,
#     db: Session = Depends(get_db),  # Properly inject DB dependency
# ):
#     """
#     Generates a verification code, saves it to the database, and sends it to the seller via email or SMS.
    
#     Parameters:
#     - payload (VerificationPayload): The verification details received in the request.
#     - db (Session): Database session instance.
    
#     Returns:
#     - dict: Success or failure message.
#     """
#     try:
#         logging.info("Generating verification code for seller.")
        
#         # Extract necessary information
#         contact = payload.contact
#         is_email = payload.is_email
#         sellerId = payload.sellerId
#         seller_type = payload.seller_type
        
#         # Generate verification code
#         verification_code = generate_verification_code()
#         logging.info(f"Generated verification code: {verification_code}")
        
#         # Define expiration time (e.g., 10 minutes from now)
#         expiration_time = datetime.utcnow() + timedelta(minutes=10)  # ✅ Fixed the datetime issue
        
#         # Store the verification code in the database
#         store_verification_code(
#             db=db,
#             code=verification_code,
#             expiration=expiration_time,
#             is_email=is_email,
#             email=contact if is_email else None,
#             phoneNumber=contact if not is_email else None,
#             sellerId=sellerId
#         )
#         logging.info("Verification code saved to the database.")
        
#         # Send verification message
#         send_success = send_verification(contact, verification_code, seller_type, is_email)
#         if not send_success:
#             logging.error("Failed to send verification message.")
#             return {"error": "Failed to send verification message."}
        
#         return {"message": "Verification code sent successfully."}
#     except Exception as e:
#         logging.error(f"Error generating and sending verification code: {str(e)}")
#         return {"error": "Failed to generate and send verification code.", "details": str(e)}

@router.post("/verify-code", summary="Verify seller's code and notify vendor-service")
async def verify_code_endpoint(
    code: str = Body(..., embed=True),
    email: str = Body(..., embed=True),
    db: Session = Depends(get_db)
):
    try:
        logging.info(f"Received verification request: email={email}, code={code}")
        
        # Verify the email code
        result = verify_seller_code(db, code, email)
        if not result or not isinstance(result, tuple):
            logging.warning(f"Verification failed. Result: {result}")
            return {
                "isValid": False,
                "message": "Invalid verification code. Please ensure the code is correct and not expired."
            }

        is_verified, sellerId = result
        if not is_verified:
            logging.warning(f"Verification failed for email={email} and code={code}")
            return {"isValid": False, "message": "Invalid verification code"}

        if not sellerId:
            logging.error("Seller ID is missing in verification result.")
            raise HTTPException(status_code=400, detail="Seller ID is missing.")

        # Notify vendor-service
        try:
            notify_seller_service(sellerId, is_email=True)
            logging.info(f"Seller with ID {sellerId} successfully verified in vendor-service.")
        except requests.exceptions.RequestException as notify_error:
            logging.error(f"Failed to notify vendor-service: {notify_error}")
            # Gracefully handle failure (Alternative 1: Raise exception)
            raise HTTPException(status_code=500, detail="Verification succeeded, but notification failed.")
            # Alternative 2: Proceed even if notification fails
            # return {
            #     "isValid": True,
            #     "message": "Email verification succeeded, but we could not update the vendor-service. Please contact support."
            # }

        return {"isValid": True, "message": "Email verification successful"}
    
    except HTTPException as e:
        logging.error(f"HTTPException in verify_code_endpoint: {e}")
        raise e
    except Exception as e:
        logging.error(f"Unexpected error in verify_code_endpoint: {e}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred during verification")




@router.get("/verify", summary="Verify code via link")
async def verify_code_via_link(
    email: str,
    code: str,
    db: Session = Depends(get_db)
):
    try:
        # Log the incoming verification attempt
        logging.info(f"Verifying code {code} for email {email}")

        # Verify the seller code
        is_verified, sellerId = verify_seller_code(db, code, email)
        logging.info(f"Verification result: is_verified={is_verified}, sellerId={sellerId}")

        # Handle invalid verification
        if not is_verified:
            return {"isValid": False, "message": "Invalid verification code"}

        # Notify the seller service
        try:
            notify_seller_service(sellerId, is_email=True)
            logging.info(f"Successfully notified seller service for sellerId={sellerId}")
        except Exception as e:
            logging.error(f"Failed to notify seller service for sellerId={sellerId}: {e}")
            # Return success for verification but warn about notification failure
            return {
                "isValid": True,
                "message": "Verification successful, but notification failed. Please contact support."
            }

        # Return success response if everything goes well
        return {"isValid": True, "message": "Verification successful"}
    except Exception as e:
        # Catch any unexpected errors and log details
        logging.error(f"Error verifying code via link: {e}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="Failed to verify code")

# @router.post("/verify-code", summary="Verify seller's code and notify vendor-service")
# async def verify_code_endpoint(request: Request, db: Session = Depends(get_db)):
#     """
#     Endpoint to verify the seller's code and notify vendor-service upon successful verification.
#     """
#     try:
#         # Log the received request payload
#         request_body = await request.json()
#         logging.info(f"[Backend] Received verification request payload: {request_body}")

#         # Extract code and email
#         code = request_body.get("code")
#         email = request_body.get("email")

#         if not code or not email:
#             logging.warning("[Backend] Missing 'code' or 'email' in request payload.")
#             raise HTTPException(status_code=400, detail="Missing required fields: code and email.")

#         logging.info(f"[Backend] Verifying code: {code} for email: {email}")

#         # Verify the seller code
#         is_valid, sellerId = verify_seller_code(db, code, email)

#         if not is_valid or not sellerId:
#             logging.warning("[Backend] Invalid or expired verification code.")
#             raise HTTPException(status_code=400, detail="Invalid or expired verification code.")

#         # Notify vendor-service (assuming you have a function)
#         notify_seller_service(sellerId=sellerId, is_email=True)
#         logging.info(f"[Backend] Successfully verified seller ID {sellerId} and notified vendor-service.")

#         return {"message": "Seller verification successful and vendor-service notified."}

#     except HTTPException as e:
#         logging.error(f"[Backend] HTTP error during verification: {str(e)}")
#         raise e
#     except Exception as e:
#         logging.error(f"[Backend] Unexpected error: {str(e)}")
#         raise HTTPException(status_code=500, detail="Internal server error.")
