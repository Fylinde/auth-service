from app.models.verification_code import VerificationCodeModel  # Replace with your actual model
import logging

def store_verification_code(db, code, expiration, is_email, email=None, phoneNumber=None, sellerId=None):
    logging.info(f"[store_verification_code] Storing code {code} for sellerId={sellerId}")

    verification_entry = VerificationCodeModel(
        email=email,
        phoneNumber=phoneNumber,
        code=code,
        expires_at=expiration,
        is_email=is_email,
        sellerId=sellerId
    )
    db.add(verification_entry)
    db.commit()
    logging.info(f"[store_verification_code] Successfully stored verification code {code} for sellerId={sellerId}")
