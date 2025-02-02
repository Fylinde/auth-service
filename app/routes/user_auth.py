from fastapi import APIRouter, Depends, Query, HTTPException, Form
from sqlalchemy.orm import Session
from app.database import get_db
from app.services.user_auth import (
    verify_2fa_and_issue_tokens, 
    update_user, 
    delete_user

)

from app.schemas.auth_schemas import (
    TwoFactorVerifyRequest, 
    TokenResponse 

)


from app.schemas.auth_schemas import SessionCreate
from fastapi.security import OAuth2PasswordRequestForm
from app.services.auth_login_service import verify_otp_code
from app.schemas.two_factor import Enable2FARequest, MessageResponse, OTPRequest
from app.services.auth_login_service import get_user_by_contact, enable_user_2fa, disable_user_2fa, create_access_token, create_refresh_token
from app.security import oauth2_scheme
from app.utils.token_utils import get_user_id_from_token, generate_otp, generate_and_store_otp
from app.utils.email_service import send_otp_to_contact
from app.services.auth_login_service import verify_user_credentials
from datetime import timedelta
from app.config import settings
import os
from app.services.logout_service import logout_user_service
from app.schemas.logout import LogoutRequest, LogoutResponse 
from app.crud.session_crud import create_session
from datetime import datetime
from fastapi.responses import RedirectResponse
import requests
import logging
from app.schemas.otp_schemas import OTPResponse 
from app.utils.token_utils import save_otp_to_database
router = APIRouter()

SECRET_KEY = os.getenv("SECRET_KEY", settings.SECRET_KEY)
OTP_VALIDITY_DURATION = int(os.getenv("OTP_VALIDITY_DURATION", "300"))
ALGORITHM: str = os.getenv("ALGORITHM", settings.ALGORITHM)
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
REFRESH_TOKEN_EXPIRE_DAYS  = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS ", "7"))
USER_SERVICE_URL = os.getenv("USER_SERVICE_URL", settings.USER_SERVICE_URL)



# Update user information
@router.put("/update")
def update_user_info(user_data: dict, token: str):
    return update_user(token=token, user_data=user_data)

# Delete user account
@router.delete("/delete")
def delete_user_account(token: str):
    return delete_user(token=token)

# Verify 2FA for user and issue tokens
@router.post("/verify-2fa", response_model=TokenResponse)
def verify_2fa_user(request: TwoFactorVerifyRequest, db: Session = Depends(get_db)):
    return verify_2fa_and_issue_tokens(user_id=request.user_id, code=request.code, db=db)


@router.get("/verify", response_model=TokenResponse, summary="Verify user email with a code")
async def verify_email(
    code: str = Query(..., description="Verification code", min_length=4, max_length=6),
    redirect: bool = Query(False, description="Redirect to frontend with token")
):
    user_service_url = f"{USER_SERVICE_URL}/verify-code?code={code}"
    logging.info(f"Attempting to verify code via user-service: {user_service_url}")
    
    try:
        # Request verification from user-service
        response = requests.get(user_service_url)
        response.raise_for_status()
        verification_data = response.json()
        logging.info(f"User-service response data: {verification_data}")
        
        # Check if verification was successful
        verification_success = verification_data.get("verified", False)
        
        if verification_success:
            user_id = verification_data["user"]["id"]
            is_admin = verification_data["user"].get("is_admin", False)
            logging.info(f"User {user_id} verified successfully, is_admin: {is_admin}")
            
            # Generate tokens
            access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            access_token = create_access_token(
                data={"user_id": user_id, "is_admin": is_admin}, 
                expires_delta=access_token_expires
            )
            refresh_token_expires = timedelta(days=7)
            refresh_token = create_refresh_token(
                data={"user_id": user_id}, 
                expires_delta=refresh_token_expires
            )
            
            if redirect:
                # Redirect to frontend with tokens in the URL
                frontend_url = f"http://localhost:3000/user-dashboard?access_token={access_token}&refresh_token={refresh_token}"
                return RedirectResponse(url=frontend_url)

            # Return tokens directly if not redirecting
            return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}
        
        logging.error("Verification failed: user not verified by user-service.")
        raise HTTPException(status_code=400, detail="Verification failed.")
    
    except requests.HTTPError as e:
        logging.error(f"Verification failed for code {code}: {e}")
        raise HTTPException(status_code=response.status_code, detail="Verification failed: code not found.")
    except requests.RequestException as e:
        logging.error(f"User-service connection error: {e}")
        raise HTTPException(status_code=500, detail="User-service unavailable.")

    

@router.post("/login", response_model=MessageResponse)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    # Call verify_user_credentials with only username and password
    user_data = verify_user_credentials(form_data.username, form_data.password)

    # Send OTP to the user after successful initial login
    otp_code = generate_and_store_otp(db, user_data["id"])
    send_otp_to_contact(user_data["contact_info"], otp_code)
    
    return {"message": "A 2FA code has been sent to your registered contact method."}


    
    
@router.post("/enable-2fa", response_model=MessageResponse)
def enable_2fa(
    data: Enable2FARequest,
    token: str = Depends(oauth2_scheme)
):
    user_id = get_user_id_from_token(token)  # This should be a helper function to decode the token and get user ID
    response = enable_user_2fa(user_id, data.code)
    return {"message": response["message"]}

@router.post("/disable-2fa", response_model=MessageResponse)
def disable_2fa(
    token: str = Depends(oauth2_scheme)
):
    user_id = get_user_id_from_token(token)
    response = disable_user_2fa(user_id)
    return {"message": response["message"]}

@router.post("/send-otp", response_model=OTPResponse)
def send_otp(
    request: OTPRequest,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    user_id = get_user_id_from_token(token)
    otp_code = generate_otp()
    expires_at = datetime.utcnow() + timedelta(minutes=5)

    # Save the OTP code in the database
    save_otp_to_database(db, user_id, otp_code)

    # Send the OTP to the user
    send_otp_to_contact(request.email or request.phoneNumber, otp_code)
    
    return OTPResponse(otp_code=otp_code, expires_at=expires_at)



@router.post("/verify-otp", response_model=TokenResponse)
def verify_otp(contact: str = Form(...), otp: str = Form(...), db: Session = Depends(get_db)):
    # Fetch user data by contact
    user_data = get_user_by_contact(contact)
    if not user_data:
        raise HTTPException(status_code=404, detail="User not found")

    user_id = user_data["id"]
    if not verify_otp_code(db, user_id, otp):
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    # Generate access and refresh tokens
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"user_id": user_id}, expires_delta=access_token_expires)
    refresh_token_expires = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    refresh_token = create_refresh_token(data={"user_id": user_id}, expires_delta=refresh_token_expires)

    # Create session data
    session_data = SessionCreate(
        user_id=user_id,
        session_token=access_token,
        expires_at=datetime.utcnow() + access_token_expires,
        is_valid=True
    )
    create_session(db, session_data)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer"
    )

    

@router.post("/logout", response_model=LogoutResponse)
def logout(
    request: LogoutRequest,  # Accepts a request body
    db: Session = Depends(get_db),
    session_token: str = Depends(oauth2_scheme)
):
    if session_token != request.session_token:
        raise HTTPException(status_code=403, detail="Invalid token")

    response = logout_user_service(db, request.session_token)
    return response


