from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.services.seller_auth import (
    authenticate_seller_with_2fa, 
    verify_2fa_and_issue_tokens, 
    update_seller, 
    delete_seller
)

from app.schemas.auth_schemas import SellerLogin, TwoFactorVerifyRequest, TokenResponse

router = APIRouter()

# seller login (initial step, sends 2FA code)
@router.post("/login", response_model=TokenResponse)
def seller_login(credentials: SellerLogin, db: Session = Depends(get_db)):
    return authenticate_seller_with_2fa(email=credentials.email, password=credentials.password)


# Update seller information
@router.put("/update")
def update_seller_info(seller_data: dict, token: str):
    return update_seller(token=token, seller_data=seller_data)

# Delete seller account
@router.delete("/delete")
def delete_seller_account(token: str):
    return delete_seller(token=token)


# Verify 2FA for seller and issue tokens
@router.post("/verify-2fa", response_model=TokenResponse)
def verify_2fa_seller(request: TwoFactorVerifyRequest, db: Session = Depends(get_db)):
    return verify_2fa_and_issue_tokens(user_id=request.user_id, code=request.code, db=db)

