from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.vendor import VendorModel
from app.schemas.token import Token
from app.schemas.vendor_schemas import VendorResponse, VendorCreate
from app.security import check_role, TokenData, verify_password, create_access_token, get_password_hash
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from app. schemas.vendor_schemas import VendorLogin

router = APIRouter()

@router.post("/register", response_model=VendorResponse)
def register_vendor(vendor: VendorCreate, db: Session = Depends(get_db)):
    db_vendor = db.query(VendorModel).filter(VendorModel.email == vendor.email).first()
    if db_vendor:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = get_password_hash(vendor.password)  # Hash the password
    new_vendor = VendorModel(
        name=vendor.name,
        email=vendor.email,
        description=vendor.description,
        rating=vendor.rating,
        hashed_password=hashed_password  # Store the hashed password
    )
    db.add(new_vendor)
    db.commit()
    db.refresh(new_vendor)
    return new_vendor

@router.post("/login")
def vendor_login(credentials: VendorLogin, db: Session = Depends(get_db)):
    db_vendor = db.query(VendorModel).filter(VendorModel.email == credentials.email).first()
    if not db_vendor or not verify_password(credentials.password, db_vendor.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    token = create_access_token(data={"user_id": db_vendor.id, "role": "vendor"})
    return {"access_token": token, "token_type": "bearer"}

