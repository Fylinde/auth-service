from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.admin import AdminModel  # Use AdminModel
from app.models.user import UserModel
from app.schemas.user_schemas import UserResponse, UserCreate
from app.schemas.two_factor import Message
from app.schemas.admin import RoleUpdate, LockAccountRequest, UnlockAccountRequest, AdminCreate, AdminLogin
from app.security import check_role, TokenData, verify_password, create_access_token
import logging
from app.utils.password_utils import get_password_hash
from datetime import datetime
import os
from app.config import settings
router = APIRouter()

ADMIN_SECRET_KEY = os.getenv("ADMIN_SECRET_KEY")

@router.get("/users", dependencies=[Depends(check_role("admin"))])
def list_users(db: Session = Depends(get_db)):
    users = db.query(AdminModel).all()
    return users

@router.put("/deactivate-user/{user_id}", response_model=UserResponse)
def deactivate_user(user_id: int, db: Session = Depends(get_db), current_user: TokenData = Depends(check_role("admin"))):
    db_user = db.query(AdminModel).filter(AdminModel.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    db_user.is_active = False
    db.commit()
    db.refresh(db_user)
    return db_user

@router.put("/activate-user/{user_id}", response_model=UserResponse)
def activate_user(user_id: int, db: Session = Depends(get_db), current_user: TokenData = Depends(check_role("admin"))):
    db_user = db.query(AdminModel).filter(AdminModel.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    db_user.is_active = True
    db.commit()
    db.refresh(db_user)
    return db_user

@router.put("/user/role", dependencies=[Depends(check_role("admin"))])
def update_role(request: RoleUpdate, db: Session = Depends(get_db)):
    db_user = db.query(AdminModel).filter(AdminModel.username == request.username).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    db_user.role = request.role
    db.commit()
    db.refresh(db_user)
    return {"message": "User role updated successfully"}

@router.delete("/user/{user_id}", dependencies=[Depends(check_role("admin"))])
def delete_user(user_id: int, db: Session = Depends(get_db)):
    db_user = db.query(AdminModel).filter(AdminModel.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    db.delete(db_user)
    db.commit()
    return {"message": "User deleted successfully"}

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

@router.post("/register", response_model=UserResponse)
def register_admin(admin: AdminCreate, db: Session = Depends(get_db)):
    if admin.secret_key != settings.ADMIN_SECRET_KEY:
        raise HTTPException(status_code=403, detail="Invalid secret key")
    
    db_user = db.query(AdminModel).filter(AdminModel.email == admin.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = get_password_hash(admin.password)
    new_admin = AdminModel(
        username=admin.username, 
        email=admin.email, 
        hashed_password=hashed_password, 
        role="admin"
    )
    db.add(new_admin)
    db.commit()
    db.refresh(new_admin)
    return new_admin

@router.post("/login")
def admin_login(credentials: AdminLogin, db: Session = Depends(get_db)):
    db_user = db.query(UserModel).filter(UserModel.email == credentials.email).first()
    if not db_user or not verify_password(credentials.password, db_user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    if db_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    token = create_access_token(data={"user_id": db_user.id, "role": "admin"})
    return {"access_token": token, "token_type": "bearer"}

