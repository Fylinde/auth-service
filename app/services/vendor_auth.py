import requests
from fastapi import HTTPException
from app.security import create_access_token, create_refresh_token
from app.utils.rabbitmq import RabbitMQConnection
from datetime import datetime
import os
from datetime import timedelta, datetime
from app.crud.session_crud import create_session
from app.schemas.auth_schemas import SessionCreate
from sqlalchemy.orm import Session
from app.config import settings
# RabbitMQ setup for publishing events
rabbitmq = RabbitMQConnection(exchange_name="auth_events", exchange_type="fanout")



# Define constants
SECRET_KEY = os.getenv("SECRET_KEY", settings.SECRET_KEY)
ALGORITHM = os.getenv("ALGORITHM", settings.ALGORITHM)
ACCESS_TOKEN_EXPIRE_MINUTES = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", settings.ACCESS_TOKEN_EXPIRE_MINUTES)


# Vendor-service URL (configured in environment)
VENDOR_SERVICE_URL = os.getenv("VENDOR_SERVICE_URL", "http://vendor-service/api/vendors")

def authenticate_vendor(email: str, password: str):
    """
    Authenticate the vendor by making an API call to the vendor-service.
    If authentication is successful, return the access token and publish a login event.
    """
    response = requests.post(f"{VENDOR_SERVICE_URL}/authenticate", json={
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
    vendor_data = response.json()
    access_token = create_access_token(data={"vendor_id": vendor_data['id'], "is_vendor": True})

    event = {
        "event": "vendor_logged_in",
        "vendor_id": vendor_data['id'],
        "email": vendor_data['email'],
        "login_time": datetime.utcnow().isoformat()
    }
    rabbitmq.publish_message(event)

    return {"access_token": access_token, "token_type": "bearer"}

def change_vendor_password(token: str, current_password: str, new_password: str):
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.post(f"{VENDOR_SERVICE_URL}/change-password", json={
        "current_password": current_password,
        "new_password": new_password
    }, headers=headers)

    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Password change failed")

    vendor_data = response.json()
    event = {
        "event": "password_changed",
        "vendor_id": vendor_data['id'],
        "email": vendor_data['email'],
        "change_time": datetime.utcnow().isoformat()
    }
    rabbitmq.publish_message(event)

    return {"message": "Password changed successfully"}

def update_vendor(token: str, vendor_data: dict):
    """
    Update the vendor details by calling the vendor-service.
    """
    headers = {"Authorization": f"Bearer {token}"}
    
    response = requests.put(f"{VENDOR_SERVICE_URL}/update", json=vendor_data, headers=headers)
    
    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Vendor update failed")
    
    return response.json()  # Return the updated vendor data

def delete_vendor(token: str):
    """
    Delete the vendor by calling the vendor-service.
    """
    headers = {"Authorization": f"Bearer {token}"}
    
    response = requests.delete(f"{VENDOR_SERVICE_URL}/delete", headers=headers)
    
    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Vendor deletion failed")
    
    return {"message": "Vendor deleted successfully"}


def authenticate_vendor_with_2fa(email: str, password: str):
    """
    Authenticate the vendor by making an API call to the vendor-service.
    After successful authentication, generate and send a 2FA code.
    """
    response = requests.post(f"{VENDOR_SERVICE_URL}/authenticate", json={
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

    # If authentication succeeds, vendor-service returns vendor data
    vendor_data = response.json()

    # Generate and send the 2FA code using vendor-service
    response = requests.post(f"{VENDOR_SERVICE_URL}/2fa/generate", json={"vendor_id": vendor_data['id']})
    
    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Failed to send 2FA code")

    return {"message": "2FA code sent"}


def verify_2fa_and_issue_tokens(vendor_id: int, code: str, db: Session):
    """
    Verify the 2FA code for the vendor and issue the access and session tokens if valid.
    """
    # Verify the 2FA code with the vendor-service
    response = requests.post(f"{VENDOR_SERVICE_URL}/2fa/verify", json={"vendor_id": vendor_id, "code": code})

    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Invalid 2FA code")

    # If the 2FA code is valid, proceed to issue tokens
    vendor_data = response.json()

    # Create access and refresh tokens
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"vendor_id": vendor_data['id'], "is_vendor": True},
        expires_delta=access_token_expires
    )

    refresh_token_expires = timedelta(days=7)
    refresh_token = create_refresh_token(
        data={"vendor_id": vendor_data['id']}, expires_delta=refresh_token_expires
    )

    session_token_expires = datetime.utcnow() + timedelta(hours=1)  # Session expires in 1 hour
    session_token = create_access_token(
        data={"vendor_id": vendor_data['id']},
        expires_delta=timedelta(hours=1)  # Session token expiry
    )

    # Save the session in the database
    create_session(db=db, session=SessionCreate(
        user_id=vendor_data['id'],  # Note: Adjust if needed for vendor-specific sessions
        session_token=session_token,
        expires_at=session_token_expires,
        is_valid=True
    ))

    # Publish vendor logged in event
    event = {
        "event": "vendor_logged_in",
        "vendor_id": vendor_data['id'],
        "email": vendor_data['email'],
        "login_time": datetime.utcnow().isoformat()
    }
    rabbitmq.publish_message(event)

    # Return tokens including the session token
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "refresh_token": refresh_token,
        "session_token": session_token,
        "vendor": {
            "id": vendor_data['id'],
            "name": vendor_data['name'],
            "email": vendor_data['email']
        }
    }
