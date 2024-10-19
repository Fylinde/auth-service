import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
from itsdangerous import URLSafeTimedSerializer

from app.config import settings

# Initialize the URLSafeTimedSerializer with a secret key
s = URLSafeTimedSerializer(settings.SECRET_KEY)
SECURITY_PASSWORD_SALT = settings.SECURITY_PASSWORD_SALT

def send_email(to_email, subject, body):
    try:
        # Set up the SMTP server
        smtp_server = "smtp.gmail.com"
        smtp_port = 587
        sender_email = settings.GMAIL_USER
        password = settings.GMAIL_PASSWORD

        # Create a MIMEText object to represent the email
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        # Connect to the SMTP server and send the email
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

def send_verification_email(to_email: str, verification_code: str):
    subject = "Email Verification"
    verification_link = f"http://localhost:8000/auth/verify?code={verification_code}"
    body = (f"Please verify your email by clicking on the following link: {verification_link}\n\n"
            f"Alternatively, you can enter the following verification code on the verification form: {verification_code}")

    logging.info(f"Sending verification email to {to_email} with verification code {verification_code}")
    send_email(to_email, subject, body)

def send_otp_to_contact(contact: str, otp: str):
    if "@" in contact:
        send_otp_via_email(contact, otp)
    else:
        send_sms_via_email(contact, otp)
        
def send_sms_via_email(phone_number, otp, carrier_gateway):
    recipient_email = f"{phone_number}@{carrier_gateway}"
    subject = "Your OTP Code"
    message_body = f"Your OTP code is {otp}"
    send_email(recipient_email, subject, message_body)       