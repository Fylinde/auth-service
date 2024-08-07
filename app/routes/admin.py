import logging
from fastapi import APIRouter, Depends, HTTPException, Security
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.user import UserModel  # Ensure consistent naming
from app.utils.password_utils import get_password_hash, validate_password
from app.schemas import UserResponse, RoleUpdate, UserCreate, Message
from app.security import check_role, TokenData, verify_admin_token
from datetime import datetime
from pydantic import EmailStr

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

router = APIRouter()

@router.get("/users", dependencies=[Depends(check_role("admin"))])
def list_users(db: Session = Depends(get_db)):
    users = db.query(UserModel).all()
    return users

# User management endpoints
@router.put("/deactivate-user/{user_id}", response_model=UserResponse)
def deactivate_user(user_id: int, db: Session = Depends(get_db), current_user: TokenData = Depends(check_role("admin"))):
    db_user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    db_user.is_active = False
    db.commit()
    db.refresh(db_user)
    return db_user

@router.put("/activate-user/{user_id}", response_model=UserResponse)
def activate_user(user_id: int, db: Session = Depends(get_db), current_user: TokenData = Depends(check_role("admin"))):
    db_user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    db_user.is_active = True
    db.commit()
    db.refresh(db_user)
    return db_user

@router.put("/user/role", dependencies=[Depends(check_role("admin"))])
def update_role(request: RoleUpdate, db: Session = Depends(get_db)):
    db_user = db.query(UserModel).filter(UserModel.username == request.username).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    db_user.role = request.role
    db.commit()
    db.refresh(db_user)
    return {"message": "User role updated successfully"}

# Example admin-only endpoint
@router.get("/admin-only", dependencies=[Depends(check_role("admin"))])
def read_admin_data():
    return {"message": "This is protected admin data"}

@router.delete("/user/{user_id}", dependencies=[Depends(check_role("admin"))])
def delete_user(user_id: int, db: Session = Depends(get_db)):
    db_user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    db.delete(db_user)
    db.commit()
    return {"message": "User deleted successfully"}

@router.get("/roles", dependencies=[Depends(check_role("admin"))])
def list_roles():
    roles = ["admin", "user"]
    return roles

@router.put("/set-role/{user_id}/{role}", response_model=UserResponse)
def set_role(user_id: int, role: str, db: Session = Depends(get_db), current_user: TokenData = Depends(check_role("admin"))):
    db_user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if role not in ["admin", "vendor", "customer"]:
        raise HTTPException(status_code=400, detail="Invalid role")

    db_user.role = role
    db.commit()
    db.refresh(db_user)
    return db_user

@router.post("/register_admin", response_model=UserResponse)
def register_admin(user: UserCreate, db: Session = Depends(get_db), current_user: TokenData = Depends(check_role("admin"))):
    db_user = db.query(UserModel).filter(UserModel.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    if not validate_password(user.password):
        raise HTTPException(status_code=400, detail="Password does not meet the strength requirements")

    hashed_password = get_password_hash(user.password)
    new_admin = UserModel(
        username=user.username, 
        email=user.email, 
        hashed_password=hashed_password, 
        role="admin", 
        password_last_updated=datetime.utcnow()
    )
    db.add(new_admin)
    db.commit()
    db.refresh(new_admin)
    return new_admin
