import logging
from datetime import timedelta, datetime
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Security, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
import pyotp
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
import uuid
from app.security import (
    oauth2_scheme, 
    SECRET_KEY, 
    ALGORITHM, 
    ACCESS_TOKEN_EXPIRE_MINUTES, 
    create_access_token, 
    get_current_user, 
    verify_password, 
    get_password_hash,
    authenticate_user,
    create_password_reset_token,
    verify_password_reset_token,
    create_refresh_token,
    verify_refresh_token,
    check_role,
    TokenData,
    verify_token,
    verify_admin_token
)
from app.dependencies import get_db
from app.models.user import UserModel  # Use UserModel consistently
from app.config import settings
from app.utils.email import (
    send_reset_email,
    generate_password_reset_token,
    verify_password_reset_token 
)
from app.schemas import ( 
    UserCreate, 
    UserResponse, 
    UserLogin, 
    TokenResponse, 
    UserUpdate, 
    PasswordResetRequest, 
    PasswordReset, 
    TokenRefresh, 
    Enable2FARequest, 
    UserLoginWith2FA, 
    Disable2FARequest, 
    RoleUpdate, 
    Enable2FASchema,
    Token,
    Message,
    SessionResponse,
    LockAccountRequest,
    UnlockAccountRequest
)
from app.models.session import Session
from app.utils.token_utils import create_session_token
from app.utils.password_utils import get_password_hash, validate_password
import random
import string
import requests
from app.database import SessionLocal, get_db
import os


logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

router = APIRouter()

# Ensure this is an integer
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))


# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Schemas
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: EmailStr

    class Config:
        from_attributes = True

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    session_token: Optional[str] = None
    refresh_token: Optional[str] = None

class UserUpdate(BaseModel):
    username: Optional[str]
    email: Optional[EmailStr]
    password: Optional[str]

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordReset(BaseModel):
    token: str
    new_password: str

class TokenRefresh(BaseModel):
    refresh_token: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    refresh_token: str

class TwoFactorEnableRequest(BaseModel):
    code: str

class TwoFactorVerifyRequest(BaseModel):
    code: str    

class Message(BaseModel):
    message: str

class Enable2FASchema(BaseModel):
    code: str 

class Generate2FACodeResponse(BaseModel):
    current_code: str    

class AdminLogin(BaseModel):
    email: str
    password: str

# Endpoints
import requests

@router.post("/register", response_model=UserResponse)
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(UserModel).filter(UserModel.email == user.email).first()
    if db_user:
        logging.info(f"Registration attempt failed: Email already registered - {user.email}")
        raise HTTPException(status_code=400, detail="Email already registered")
    
    if not validate_password(user.password):
        raise HTTPException(status_code=400, detail="Password does not meet the strength requirements")

    hashed_password = get_password_hash(user.password)
    two_factor_secret = pyotp.random_base32()
    new_user = UserModel(
        username=user.username, 
        email=user.email, 
        hashed_password=hashed_password, 
        two_factor_secret=two_factor_secret,
        role="user",  # Default role
        password_last_updated=datetime.utcnow()
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Create user in user-service
    user_service_url = "http://user-service:8001/users/"
    user_data = {
        "username": user.username,
        "email": user.email,
        "password": user.password,
        "profile_picture": None,
        "preferences": None
    }

    try:
        logging.info(f"Sending request to user-service at {user_service_url}")
        response = requests.post(user_service_url, json=user_data)
        response.raise_for_status()  # This will raise an HTTPError if the response was an error
        logging.info(f"Response from user-service: {response.status_code} - {response.json()}")
    except requests.RequestException as e:
        logging.error(f"Request to user-service failed: {e}")
        logging.error(f"Response from user-service: {response.text if response else 'No response'}")
        raise HTTPException(status_code=500, detail="Failed to create user in user-service")

    logging.info(f"Generated 2FA secret for {user.username}: {two_factor_secret}")
    logging.info(f"Role for {user.username}: {new_user.role}")
    return new_user


@router.post("/login", response_model=Token)
def login(payload: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.email == payload.username).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"user_id": user.id, "role": user.role}, expires_delta=access_token_expires
    )

    refresh_token_expires = timedelta(days=7)
    refresh_token = create_refresh_token(
        data={"user_id": user.id}, expires_delta=refresh_token_expires
    )

    session_token = str(uuid.uuid4().hex)
    new_session = Session(
        user_id=user.id,
        session_token=session_token,
        created_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(days=7),
        is_valid=True
    )

    db.add(new_session)
    db.commit()
    db.refresh(new_session)

    return {"access_token": access_token, "token_type": "bearer", "session_token": session_token, "refresh_token": refresh_token}




@router.post("/lock", response_model=Message)
def lock_account(request: LockAccountRequest, db: Session = Depends(get_db), current_user: TokenData = Depends(check_role("admin"))):
    email = request.email
    logging.info(f"Attempting to lock account for email: {email}")
    db_user = db.query(UserModel).filter(UserModel.email == email).first()
    if not db_user:
        logging.error(f"User not found for email: {email}")
        raise HTTPException(status_code=404, detail="User not found")
    
    db_user.account_locked = True
    db.commit()
    logging.info(f"Account locked for email: {email}")
    return {"message": "Account locked successfully"}

@router.post("/unlock", response_model=Message)
def unlock_account(request: UnlockAccountRequest, db: Session = Depends(get_db), current_user: TokenData = Depends(check_role("admin"))):
    email = request.email
    logging.info(f"Attempting to unlock account for email: {email}")
    db_user = db.query(UserModel).filter(UserModel.email == email).first()
    if not db_user:
        logging.error(f"User not found for email: {email}")
        raise HTTPException(status_code=404, detail="User not found")
    
    db_user.account_locked = False
    db.commit()
    logging.info(f"Account unlocked for email: {email}")
    return {"message": "Account unlocked successfully"}

@router.post("/admin/login")
def admin_login(credentials: AdminLogin, db: Session = Depends(get_db)):
    db_user = db.query(UserModel).filter(UserModel.email == credentials.email).first()
    if not db_user or not verify_password(credentials.password, db_user.hashed_password):
        raise HTTPException(statusverify_refresh_token_code=400, detail="Invalid credentials")
    if db_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    token = create_access_token(data={"sub": db_user.email, "role": "admin"})
    return {"access_token": token, "token_type": "bearer"}

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

@router.post("/password-reset-request")
async def password_reset_request(request: PasswordResetRequest, db: Session = Depends(get_db)):
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
def enable_2fa(data: Enable2FASchema, db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    username: str = payload.get("sub")
    if username is None:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

    db_user = db.query(UserModel).filter(UserModel.username == username).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    totp = pyotp.TOTP(db_user.two_factor_secret)
    if not totp.verify(data.code, valid_window=1):
        raise HTTPException(status_code=400, detail="Invalid 2FA code")

    db_user.two_factor_enabled = True
    db_user.backup_codes = generate_backup_codes()
    db.commit()

    return {"message": "2FA enabled successfully", "backup_codes": db_user.backup_codes}

@router.get("/generate-2fa-code", response_model=Generate2FACodeResponse)
def generate_2fa_code(username: str, db: Session = Depends(get_db)):
    try:
        logger.info(f"Fetching user with username: {username}")
        db_user = db.query(UserModel).filter(UserModel.username == username).first()
        if not db_user:
            logger.error(f"User not found: username='{username}'")
            raise HTTPException(status_code=404, detail="User not found")
        
        logger.info(f"User's 2FA secret: {db_user.two_factor_secret}")
        
        totp = pyotp.TOTP(db_user.two_factor_secret)
        current_code = totp.now()
        
        logger.info(f"Generated TOTP code for user {username}: {current_code}")
        
        return {"current_code": current_code}
    except Exception as e:
        logger.exception("An error occurred while generating the 2FA code")
        raise HTTPException(status_code=500, detail="Internal Server Error")

@router.post("/disable-2fa", response_model=Message)
def disable_2fa(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    username: str = payload.get("sub")
    if username is None:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

    db_user = db.query(UserModel).filter(UserModel.username == username).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    db_user.two_factor_enabled = False
    db.commit()
    return {"message": "2FA disabled successfully"}

@router.post("/verify-2fa", response_model=TokenResponse)
def verify_2fa(data: Enable2FASchema, db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    try:
        logger.info(f"Received 2FA verify request with token: {token}")
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            logger.error("No username found in token")
            raise HTTPException(status_code=401, detail="Could not validate credentials")
        
        logger.info(f"Decoded JWT payload: {payload}")
        logger.info(f"Token validated successfully: username='{username}'")
        
        db_user = db.query(UserModel).filter(UserModel.username == username).first()
        if not db_user:
            logger.error(f"User not found: username='{username}'")
            raise HTTPException(status_code=404, detail="User not found")
        
        logger.info(f"User's 2FA secret: {db_user.two_factor_secret}")
        
        totp = pyotp.TOTP(db_user.two_factor_secret)
        current_code = totp.now()
        
        logger.info(f"Current TOTP code for secret {db_user.two_factor_secret}: {current_code}")
        
        if not totp.verify(data.code, valid_window=2):  # Increasing valid_window parameter
            logger.error(f"Invalid 2FA code: provided='{data.code}' expected='{current_code}'")
            raise HTTPException(status_code=400, detail="Invalid 2FA code")

        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": db_user.username}, expires_delta=access_token_expires
        )

        refresh_token_expires = timedelta(days=7)
        refresh_token = create_refresh_token(
            data={"sub": db_user.username}, expires_delta=refresh_token_expires
        )

        return {"access_token": access_token, "token_type": "bearer", "refresh_token": refresh_token}
    except JWTError as e:
        logger.exception("JWT error")
        raise HTTPException(status_code=401, detail="Could not validate credentials")
    except Exception as e:
        logger.exception("An error occurred while verifying 2FA")
        raise e

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
