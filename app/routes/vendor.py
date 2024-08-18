from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.vendor import VendorModel
from app.schemas.token import Token
from app.schemas.vendor_schemas import VendorResponse, VendorCreate
from app.security import check_role, TokenData, verify_password, create_access_token, get_password_hash
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from app. schemas.vendor_schemas import VendorLogin
import logging
import pika
import json
from app.security import pwd_context
from app.utils.rabbitmq import publish_vendor_created_event

logger = logging.getLogger("auth_service")
logging.basicConfig(level=logging.INFO)
router = APIRouter()

@router.post("/register_vendor", response_model=VendorResponse)
def register_vendor(vendor: VendorCreate, db: Session = Depends(get_db)):
    # Check if the vendor already exists
    existing_vendor = db.query(VendorModel).filter(VendorModel.email == vendor.email).first()
    if existing_vendor:
        raise HTTPException(status_code=400, detail="Vendor with this email already registered")

    # Create the vendor
    vendor_obj = VendorModel(
        name=vendor.name,
        email=vendor.email,
        description=vendor.description,
        rating=vendor.rating,
        profile_picture=vendor.profile_picture,
        preferences=vendor.preferences,
        hashed_password=pwd_context.hash(vendor.password),
    )
    db.add(vendor_obj)
    db.commit()
    db.refresh(vendor_obj)

    # Log vendor creation
    logger.info(f"Vendor created in auth-service: {vendor_obj.name} (ID: {vendor_obj.id})")

    # Prepare vendor data to publish
    vendor_data = {
        "id": vendor_obj.id,
        "name": vendor_obj.name,
        "email": vendor_obj.email,
        "description": vendor_obj.description,
        "rating": vendor_obj.rating,
        "profile_picture": vendor_obj.profile_picture,
        "preferences": vendor_obj.preferences,
        "hashed_password": vendor_obj.hashed_password,
    }
    publish_vendor_created_event(vendor_data)

    return vendor_obj

@router.post("/login")
def vendor_login(credentials: VendorLogin, db: Session = Depends(get_db)):
    db_vendor = db.query(VendorModel).filter(VendorModel.email == credentials.email).first()
    if not db_vendor or not verify_password(credentials.password, db_vendor.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    token = create_access_token(data={"user_id": db_vendor.id, "role": "vendor"})
    return {"access_token": token, "token_type": "bearer"}

