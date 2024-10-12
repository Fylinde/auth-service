from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.services.vendor_auth import (
    authenticate_vendor_with_2fa, 
    verify_2fa_and_issue_tokens, 
    update_vendor, 
    delete_vendor
)

from app.schemas.auth_schemas import VendorLogin, TwoFactorVerifyRequest, TokenResponse

from app.schemas.auth_schemas import ( 
    VendorRegistrationRequest,
    RegistrationResponse
                                      
)

from fastapi import HTTPException, status

router = APIRouter()

# Vendor login (initial step, sends 2FA code)
@router.post("/login", response_model=TokenResponse)
def vendor_login(credentials: VendorLogin, db: Session = Depends(get_db)):
    return authenticate_vendor_with_2fa(email=credentials.email, password=credentials.password)


# Update vendor information
@router.put("/update")
def update_vendor_info(vendor_data: dict, token: str):
    return update_vendor(token=token, vendor_data=vendor_data)

# Delete vendor account
@router.delete("/delete")
def delete_vendor_account(token: str):
    return delete_vendor(token=token)


# Verify 2FA for vendor and issue tokens
@router.post("/verify-2fa", response_model=TokenResponse)
def verify_2fa_vendor(request: TwoFactorVerifyRequest, db: Session = Depends(get_db)):
    return verify_2fa_and_issue_tokens(user_id=request.user_id, code=request.code, db=db)

