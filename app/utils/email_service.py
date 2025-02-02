import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
from app.utils.carrier_gateways import get_carrier_gateway
from app.utils.phone_utils import validate_phone_number
from itsdangerous import URLSafeTimedSerializer

from app.config import settings

# Initialize the URLSafeTimedSerializer with a secret key
s = URLSafeTimedSerializer(settings.SECRET_KEY)
SECURITY_PASSWORD_SALT = settings.SECURITY_PASSWORD_SALT

def send_email(to_email, subject, body):
    try:
        smtp_server = "smtp.gmail.com"
        smtp_port = 587
        sender_email = settings.GMAIL_USER
        password = settings.GMAIL_PASSWORD

        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, password)
        server.sendmail(sender_email, to_email, msg.as_string())
        server.quit()

        logging.info(f"Email sent to {to_email} successfully.")
    except Exception as e:
        logging.error(f"Failed to send email to {to_email}. Error: {e}")


# Handle password reset email
def send_reset_email(to_email: str, reset_token: str):
    subject = "Password Reset Request"
    message_body = f"Your password reset token is: {reset_token}"
    send_email(to_email, subject, message_body)

# Handle OTP sending via email
def send_otp_via_email(to_email: str, otp_code: str):
    subject = "Your OTP Code"
    message_body = f"Your OTP code is: {otp_code}"
    send_email(to_email, subject, message_body)

# Retain password reset token generation
def generate_password_reset_token(email):
    return s.dumps(email, salt=SECURITY_PASSWORD_SALT)

# Verify the reset token
def verify_password_reset_token(token, expiration=3600):
    try:
        email = s.loads(token, salt=SECURITY_PASSWORD_SALT, max_age=expiration)
    except Exception as e:
        logging.error(f"Error verifying token: {e}")
        return None
    return email

# Assuming this is in auth-service/app/utils/email_utils.py

def send_verification_email(to_email: str, subject: str, body: str):
    logging.info(f"Sending verification email to {to_email} with message: {body}")
    send_email(to_email, subject, body)
    


def send_otp_to_contact(contact: str, otp: str):
    if "@" in contact:
        send_otp_via_email(contact, otp)
    else:
        send_sms_via_email(contact, otp)
        
def send_sms_via_email(phoneNumber: str, message_body: str, carrier: str = "AT&T"):
    """
    Sends an SMS via email gateway.
    Validates the phone number and resolves the carrier gateway before sending.
    """
    # Validate the phone number
    if not validate_phone_number(phoneNumber):
        logging.error(f"Invalid phone number: {phoneNumber}")
        return False

    # Resolve the carrier gateway
    carrier_gateway = get_carrier_gateway(carrier)
    recipient_email = f"{phoneNumber}@{carrier_gateway}"

    # Compose the SMS
    subject = "Your Verification Code"
    logging.info(f"Sending SMS to {recipient_email} with message: {message_body}")

    try:
        send_email(recipient_email, subject, message_body)
        logging.info(f"SMS sent successfully to {phoneNumber} via {carrier}")
        return True
    except Exception as e:
        logging.error(f"Failed to send SMS to {phoneNumber} via {carrier}: {e}", exc_info=True)
        return False
     