import requests
from fastapi import HTTPException
from app.security import create_access_token, create_refresh_token
from app.utils.rabbitmq import RabbitMQConnection
from datetime import datetime
import os
from app.schemas.auth_schemas import SessionCreate
from sqlalchemy.orm import Session
from app.crud.session_crud import create_session
from app.config import settings
from datetime import timedelta
from app.crud.user_crud import verify_user_code
#from app.services.auth_registration_service import publish_user_to_rabbitmq
import logging
#from app.config import USER_SERVICE_URL


logger = logging.getLogger(__name__)


# RabbitMQ setup for publishing events
rabbitmq = RabbitMQConnection(exchange_name="auth_events", exchange_type="fanout")

# Define constants
SECRET_KEY = os.getenv("SECRET_KEY", settings.SECRET_KEY)
ALGORITHM = os.getenv("ALGORITHM", settings.ALGORITHM)
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 15))  # Default to 15 minutes if not set

# User-service URL (configured in environment)
USER_SERVICE_URL = os.getenv("USER_SERVICE_URL", "http://localhost:8001/users")

def authenticate_user(email: str, password: str):
    """
    Authenticate the user by making an API call to the user-service.
    If authentication is successful, return the access token and publish a login event.
    """
    response = requests.post(f"{USER_SERVICE_URL}/authenticate", json={
        "email": email,
        "password": password
    })

    if response.status_code != 200:
        # Failed login attempt: publish event
        event = {
            "event": "failed_login_attempt",
            "email": email,
            "attempt_time": datetime.utcnow().isoformat()
        }
        rabbitmq.publish_message(event)
        raise HTTPException(status_code=400, detail="Invalid credentials")

    # Successful authentication: Generate token and publish event
    user_data = response.json()
    access_token = create_access_token(data={"user_id": user_data['id'], "is_user": True})

    event = {
        "event": "user_logged_in",
        "user_id": user_data['id'],
        "email": user_data['email'],
        "login_time": datetime.utcnow().isoformat()
    }
    rabbitmq.publish_message(event)

    return {"access_token": access_token, "token_type": "bearer"}

def change_user_password(token: str, current_password: str, new_password: str):
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.post(f"{USER_SERVICE_URL}/change-password", json={
        "current_password": current_password,
        "new_password": new_password
    }, headers=headers)

    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Password change failed")

    user_data = response.json()
    event = {
        "event": "password_changed",
        "user_id": user_data['id'],
        "email": user_data['email'],
        "change_time": datetime.utcnow().isoformat()
    }
    rabbitmq.publish_message(event)

    return {"message": "Password changed successfully"}

def update_user(token: str, user_data: dict):
    """
    Update the user details by calling the user-service.
    """
    headers = {"Authorization": f"Bearer {token}"}
    
    response = requests.put(f"{USER_SERVICE_URL}/update", json=user_data, headers=headers)
    
    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="User update failed")
    
    return response.json()  # Return the updated user data

def delete_user(token: str):
    """
    Delete the user by calling the user-service.
    """
    headers = {"Authorization": f"Bearer {token}"}
    
    response = requests.delete(f"{USER_SERVICE_URL}/delete", headers=headers)
    
    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="User deletion failed")
    
    return {"message": "User deleted successfully"}

def authenticate_user_with_2fa(email: str, password: str):
    # Step 1: Authenticate user with email and password via user-service
    response = requests.post(f"{USER_SERVICE_URL}/authenticate", json={"email": email, "password": password})
    
    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    
    user_data = response.json()

    # Step 2: Generate and send 2FA code (via user-service)
    response = requests.post(f"{USER_SERVICE_URL}/2fa/generate", json={"user_id": user_data['id']})
    
    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Failed to send 2FA code")

    return {"message": "2FA code sent"}

def verify_2fa_and_issue_tokens(user_id: int, code: str, db: Session):
    """
    Verify the 2FA code for the user and issue the access and session tokens if valid.
    """
    # Call user-service to verify the 2FA code
    response = requests.post(f"{USER_SERVICE_URL}/2fa/verify", json={"user_id": user_id, "code": code})
    
    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Invalid 2FA code")

    # If the 2FA code is valid, proceed to issue tokens
    user_data = response.json()

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"user_id": user_data['id'], "is_admin": user_data['is_admin']},
        expires_delta=access_token_expires
    )

    refresh_token_expires = timedelta(days=7)
    refresh_token = create_refresh_token(
        data={"user_id": user_data['id']}, expires_delta=refresh_token_expires
    )

    session_token_expires = datetime.utcnow() + timedelta(hours=1)  # Session expires in 1 hour
    session_token = create_access_token(
        data={"user_id": user_data['id']},
        expires_delta=timedelta(hours=1)  # Session token expiry
    )

    # Save the session in the database
    create_session(db=db, session=SessionCreate(
        user_id=user_data['id'],
        session_token=session_token,
        expires_at=session_token_expires,
        is_valid=True
    ))

    # Return tokens including the session token
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "refresh_token": refresh_token,
        "session_token": session_token,
        "user": {
            "id": user_data['id'],
            "full_name": user_data['full_name'],
            "email": user_data['email'],
            "phone_number": user_data['phone_number'],
            "is_admin": user_data['is_admin'],
        }
    }

def verify_user_email(code: str):
    """
    Verifies a user's email by calling user-service to validate the verification code.
    """
    verification_result = verify_user_code(code)
    
    if verification_result.get("message") == "Verification successful":
        return {"message": "User email verified successfully."}
    else:
        raise HTTPException(status_code=400, detail="Verification failed.")