from fastapi import APIRouter, Depends, HTTPException, status, Security
from sqlalchemy.orm import Session
from jose import jwt, JWTError
from datetime import timedelta, datetime
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from app.security import (
    oauth2_scheme,
    SECRET_KEY,
    ALGORITHM,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    create_access_token,
    verify_password,
    get_password_hash,
    get_current_user,
    check_role,
    verify_refresh_token,
    authenticate_user,
    TokenData
)
from app.dependencies import get_db
from app.models.user import UserModel
from app.models.session import Session
from app.schemas.user_schemas import (
    UserCreate,
    UserResponse,
    UserLogin,
    UserUpdate,  
)
from app.schemas.two_factor import Enable2FARequest, TwoFactorEnableRequest, Message
from app.schemas.password import PasswordChangeRequest, PasswordReset, PasswordResetRequest
from app.schemas.session_schemas import SessionCreate, SessionResponse
from app.schemas.token import Token, TokenRefresh, TokenResponse
from app.utils.email import send_reset_email, generate_password_reset_token, verify_password_reset_token
from app.utils.password_utils import get_password_hash, validate_password
from app.utils.token_utils import create_session_token
import pyotp
import uuid
import os
import pika
import json
import random
import string
import requests
import logging
from fastapi.responses import JSONResponse
from passlib.context import CryptContext
from typing import Optional, List
from app.config import settings
from app.security import (
    verify_password, 
    create_access_token, 
    create_refresh_token
)
from app.models.session import Session as SessionModel
from app.database import SessionLocal, get_db


router = APIRouter()

# Ensure this is an integer
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60))
# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

logger = logging.getLogger(__name__)


import logging
import requests
from fastapi import HTTPException

logger = logging.getLogger(__name__)

def register_user_in_user_service(user_data):
    try:
        user_service_url = "http://user-service:8001/users/"
        response = requests.post(user_service_url, json=user_data)
        response.raise_for_status()
        logging.info(f"User created in user-service: {user_data['username']}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to create user in user-service: {e}")
        raise HTTPException(status_code=500, detail="Failed to create user in user-service")

@router.post("/register")
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    # Check if user exists in the auth-service database
    db_user = db.query(UserModel).filter(UserModel.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    # Hash the password before sending it to user-service
    hashed_password = get_password_hash(user.password)
    
    # Generate a Two-Factor Authentication secret
    two_factor_secret = pyotp.random_base32()

    # Prepare the user data for user-service
    user_data = {
        "username": user.username,
        "email": user.email,
        "password": hashed_password,  # Send the hashed password
        "profile_picture": user.profile_picture,
        "preferences": user.preferences
    }

    # Create user in user-service
    register_user_in_user_service(user_data)

    # Create user in auth-service
    new_user = UserModel(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,  # Store the hashed password in auth-service
        role="user",  # Default role
        password_last_updated=datetime.utcnow(),
        two_factor_secret=two_factor_secret  # Store the 2FA secret in the database
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Publish event to RabbitMQ
    publish_user_created_event(user_data)

    logging.info(f"Generated 2FA secret for {user.username}: {two_factor_secret}")
    logging.info(f"Role for {user.username}: {new_user.role}")
    
    return new_user

def publish_user_created_event(user_data):
    connection = pika.BlockingConnection(pika.ConnectionParameters('rabbitmq'))
    channel = connection.channel()

    channel.queue_declare(queue='user_created')

    channel.basic_publish(
        exchange='',
        routing_key='user_created',
        body=json.dumps(user_data)
    )

    connection.close()
    
@router.post("/login", response_model=Token)
def login(payload: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.email == payload.username).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")


    access_token_expires = timedelta(minutes=int(ACCESS_TOKEN_EXPIRE_MINUTES))
    access_token = create_access_token(
        data={"user_id": user.id, "role": user.role}, expires_delta=access_token_expires
    )


    refresh_token_expires = timedelta(days=7)
    refresh_token = create_refresh_token(
        data={"user_id": user.id}, expires_delta=refresh_token_expires
    )


    session_token = str(uuid.uuid4().hex)
    new_session = SessionModel(
        user_id=user.id,
        session_token=session_token,
        created_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(days=7),
        is_valid=True
    )


    db.add(new_session)
    db.commit()
    db.refresh(new_session)


    return {
        "access_token": access_token,
        "token_type": "bearer",
        "session_token": session_token,
        "refresh_token": refresh_token
    }





@router.post("/password-reset-request", response_model=Message)
def password_reset_request(request: PasswordResetRequest, db: Session = Depends(get_db)):
    db_user = db.query(UserModel).filter(UserModel.email == request.email).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")


    reset_token = generate_password_reset_token(request.email)
    send_reset_email(request.email, reset_token)
    return {"message": "Password reset token sent"}


@router.post("/password-reset")
def password_reset(reset: PasswordReset, db: Session = Depends(get_db)):
    email = verify_password_reset_token(reset.token)
    if email is None:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    
    db_user = db.query(UserModel).filter(UserModel.email == email).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not validate_password(reset.new_password):
        raise HTTPException(status_code=400, detail="Password does not meet the strength requirements")

    db_user.hashed_password = get_password_hash(reset.new_password)
    db_user.password_last_updated = datetime.utcnow()
    db.commit()
    db.refresh(db_user)
    return {"message": "Password has been reset successfully"}


@router.post("/token-refresh", response_model=Token)
def refresh_token(token_refresh: TokenRefresh, db: Session = Depends(get_db)):
    logger.info(f"Received refresh token: {token_refresh.refresh_token}")
    token_data = verify_refresh_token(token_refresh.refresh_token)
    logger.info(f"Verified token data: user_id={token_data.user_id} username={token_data.username} role={token_data.role} two_factor={token_data.two_factor}")

    try:
        db_user = db.query(UserModel).filter(UserModel.id == token_data.user_id).first()
        if not db_user:
            logger.error(f"User not found for ID: {token_data.user_id}")
            raise HTTPException(status_code=404, detail="User not found")

        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": db_user.username, "user_id": db_user.id, "role": db_user.role},
            expires_delta=access_token_expires
        )
        refresh_token_expires = timedelta(days=7)
        refresh_token = create_refresh_token(
            data={"user_id": db_user.id}, expires_delta=refresh_token_expires
        )
        return {"access_token": access_token, "token_type": "bearer", "refresh_token": refresh_token}
    except HTTPException as e:
        logger.error(f"Token refresh error: {e.detail}")
        raise e
    except Exception as e:
        logger.exception("Unexpected error during token refresh")
        raise HTTPException(status_code=500, detail="Internal Server Error")

def generate_backup_codes() -> list:
    return [''.join(random.choices(string.ascii_uppercase + string.digits, k=8)) for _ in range(10)]


@router.post("/enable-2fa", response_model=Message)
def enable_2fa(data: Enable2FARequest, db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    logging.info("Enable 2FA: Received request to enable 2FA.")
    
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    user_id: str = payload.get("user_id")
    
    if user_id is None:
        logging.error("Enable 2FA: Invalid token, no user_id found.")
        raise HTTPException(status_code=401, detail="Could not validate credentials")

    logging.info(f"Enable 2FA: Decoded user ID from token: {user_id}")

    db_user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not db_user:
        logging.error("Enable 2FA: User not found.")
        raise HTTPException(status_code=404, detail="User not found")

    logging.info(f"Enable 2FA: Found user {db_user.username} in the database.")

    totp = pyotp.TOTP(db_user.two_factor_secret)
    expected_code = totp.now()
    logging.info(f"Enable 2FA: Expected 2FA code for user {db_user.username}: {expected_code}")

    if not totp.verify(data.code, valid_window=1):
        logging.error("Enable 2FA: Invalid 2FA code.")
        raise HTTPException(status_code=400, detail="Invalid 2FA code")

    db_user.two_factor_enabled = True
    db.commit()

    logging.info(f"Enable 2FA: 2FA enabled successfully for user {db_user.username}.")
    return {"message": "2FA enabled successfully"}



@router.post("/disable-2fa", response_model=Message)
def disable_2fa(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    user_id: str = payload.get("user_id")
    if user_id is None:
        raise HTTPException(status_code=401, detail="Could not validate credentials")


    db_user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")


    db_user.two_factor_enabled = False
    db.commit()


    return {"message": "2FA disabled successfully"}



@router.post("/verify-2fa", response_model=Token)
def verify_2fa(data: Enable2FARequest, db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    logging.info("Verify 2FA: Received request to verify 2FA.")
    
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    user_id: str = payload.get("user_id")
    
    if user_id is None:
        logging.error("Verify 2FA: Invalid token, no user_id found.")
        raise HTTPException(status_code=401, detail="Could not validate credentials")

    logging.info(f"Verify 2FA: Decoded user ID from token: {user_id}")

    db_user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not db_user:
        logging.error("Verify 2FA: User not found.")
        raise HTTPException(status_code=404, detail="User not found")

    logging.info(f"Verify 2FA: Found user {db_user.username} in the database.")

    totp = pyotp.TOTP(db_user.two_factor_secret)
    if not totp.verify(data.code, valid_window=1):
        logging.error("Verify 2FA: Invalid 2FA code.")
        raise HTTPException(status_code=400, detail="Invalid 2FA code")

    logging.info(f"Verify 2FA: 2FA code verified successfully for user {db_user.username}.")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"user_id": db_user.id, "role": db_user.role}, expires_delta=access_token_expires
    )

    refresh_token_expires = timedelta(days=7)
    refresh_token = create_access_token(
        data={"user_id": db_user.id}, expires_delta=refresh_token_expires
    )

    logging.info(f"Verify 2FA: Tokens generated successfully for user {db_user.username}.")
    return {"access_token": access_token, "token_type": "bearer", "refresh_token": refresh_token}


@router.get("/test-2fa", response_model=Message)
def test_2fa(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    user_id: str = payload.get("user_id")
    if user_id is None:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

    db_user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    if not db_user.two_factor_enabled:
        raise HTTPException(status_code=400, detail="2FA is not enabled")

    return {"message": "2FA is enabled and working correctly"}


@router.get("/generate-2fa-code", response_model=Enable2FARequest)
def generate_2fa_code(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    logging.info("Generate 2FA Code: Received request to generate 2FA code.")
    
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    user_id: str = payload.get("user_id")
    
    if user_id is None:
        logging.error("Generate 2FA Code: Invalid token, no user_id found.")
        raise HTTPException(status_code=401, detail="Could not validate credentials")

    logging.info(f"Generate 2FA Code: Decoded user ID from token: {user_id}")

    db_user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not db_user:
        logging.error("Generate 2FA Code: User not found.")
        raise HTTPException(status_code=404, detail="User not found")

    logging.info(f"Generate 2FA Code: Found user {db_user.username} in the database.")

    totp = pyotp.TOTP(db_user.two_factor_secret)
    current_code = totp.now()

    logging.info(f"Generate 2FA Code: Generated 2FA code for user {db_user.username}: {current_code}")

    return {"code": current_code}


@router.post("/login")
def login_for_access_token(db: Session = Depends(get_db), form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"user_id": user.id, "username": user.username, "role": user.role},
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/sessions", response_model=List[SessionResponse])
def list_sessions(db: Session = Depends(get_db), current_user: TokenData = Depends(get_current_user)):
    sessions = db.query(Session).filter(Session.user_id == current_user.id).all()
    return sessions

@router.delete("/sessions/{session_id}")
def delete_session(session_id: int, db: Session = Depends(get_db), current_user: TokenData = Depends(get_current_user)):
    session = db.query(Session).filter(Session.id == session_id, Session.user_id == current_user.id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    db.delete(session)
    db.commit()
    return {"message": "Session deleted successfully"}

@router.get("/verify-user/{username}", response_model=UserResponse)
def verify_user(username: str, db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@router.put("/profile", response_model=UserResponse)
def update_profile(user_update: UserUpdate, db: Session = Depends(get_db), current_user: TokenData = Depends(get_current_user)):
    db_user = db.query(UserModel).filter(UserModel.username == current_user.username).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user_update.username:
        db_user.username = user_update.username
    if user_update.email:
        if db.query(UserModel).filter(UserModel.email == user_update.email).first():
            raise HTTPException(status_code=400, detail="Email already registered")
        db_user.email = user_update.email
    if user_update.password:
        db_user.hashed_password = pwd_context.hash(user_update.password)
    if user_update.role:
        db_user.role = user_update.role
    
    db.commit()
    db.refresh(db_user)
    return db_user