from sqlalchemy.orm import Session
from app.models.user import UserModel
from app.schemas.user_schemas import UserCreate, UserUpdate
from app.utils.password_utils import get_password_hash  # Import the hashing function

def create_user(db: Session, user: UserCreate):
    hashed_password = get_password_hash(user.password)  # Hash the plain-text password
    db_user = UserModel(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,  # Store the hashed password
        role=user.role
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def get_user_by_email(db: Session, email: str):
    return db.query(UserModel).filter(UserModel.email == email).first()

def get_user_by_id(db: Session, user_id: int):
    return db.query(UserModel).filter(UserModel.id == user_id).first()

def update_user(db: Session, db_user: UserModel, user_update: UserUpdate):
    for field, value in user_update.dict(exclude_unset=True).items():
        setattr(db_user, field, value)
    db.commit()
    db.refresh(db_user)
    return db_user

def delete_user(db: Session, user_id: int):
    db_user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if db_user:
        db.delete(db_user)
        db.commit()
        return True
    return False
