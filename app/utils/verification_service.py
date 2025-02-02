import logging
from app.utils.email_service import send_verification_email, send_sms_via_email
from app.config import settings


FRONTEND_URL = settings.FRONTEND_URL

# def generate_verification_link(contact: str, code: str, seller_type: str) -> str:
#     # Validate input
#     if not isinstance(seller_type, str):
#         raise ValueError(f"Expected seller_type to be a string, got {type(seller_type).__name__}.")
    
#     # Normalize seller type
#     seller_type = seller_type.strip().lower()

#     if seller_type not in ["professional", "individual"]:
#         raise ValueError("Invalid seller type. Must be 'professional' or 'individual'.")
#     logging.info(f"Generating verification link for seller_type: '{seller_type}'")

#     return f"{settings.FRONTEND_URL}/register/seller/{seller_type}/combined-information?email={contact}&code={code}"

def generate_verification_link(contact: str, code: str, seller_type: str) -> str:
    """
    Generates a verification link to be sent to the seller as a second verification option.
    
    Parameters:
    - contact (str): Seller's email or phone number.
    - code (str): Verification code received from AUTH_SERVICE.
    - seller_type (str): Type of seller, must be either "professional" or "individual".
    
    Returns:
    - str: Verification link directing to the frontend.
    """
    if seller_type not in ["professional", "individual"]:
        logging.error(f"Invalid seller type: {seller_type}")
        raise ValueError("Invalid seller type")
    
    verification_link = f"{FRONTEND_URL}/register/seller/{seller_type}/combined-information?code={code}&contact={contact}"
    logging.info(f"Generated verification link: {verification_link}")
    
    return verification_link

def send_verification(contact: str, verification_code: str, seller_type: str, is_email: bool = True, carrier: str = "AT&T") -> bool:
    try:
        # Log seller_type for debugging
        logging.info(f"send_verification called with seller_type: {seller_type}")
        
        # Ensure seller_type is a string
        if not isinstance(seller_type, str):
            logging.error(f"Invalid seller_type: {seller_type} (expected string)")
            raise ValueError("Invalid seller_type. Must be a string.")

        # Generate the dynamic verification link
        verification_link = generate_verification_link(contact, verification_code, seller_type)

        message_body = f"""
        Dear Seller,

        Your verification code is: {verification_code}

        Alternatively, you can click the link below to verify directly:
        {verification_link}

        Thank you,
        The Team
        """

        if is_email:
            send_verification_email(contact, "Seller Verification", message_body)
            logging.info(f"Email sent with verification code: {verification_code} for contact: {contact}")

        else:
            logging.info(f"Sending verification SMS to {contact} via {carrier}")
            send_sms_via_email(contact, message_body, carrier)

        logging.info(f"Verification code sent to {contact} (via {'email' if is_email else 'SMS'})")
        return True
    except Exception as e:
        logging.error(f"Failed to send verification code to {contact}: {e}")
        return False

