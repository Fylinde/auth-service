import os
import requests
import logging
from itsdangerous import URLSafeTimedSerializer

# Initialize the URLSafeTimedSerializer with a secret key
s = URLSafeTimedSerializer(os.getenv('SECRET_KEY'))
SECURITY_PASSWORD_SALT = os.getenv('SECURITY_PASSWORD_SALT')

def send_reset_email(to_email: str, reset_token: str):
    api_key = os.getenv('MAILGUN_API_KEY')
    domain = os.getenv('MAILGUN_DOMAIN')
    sender_email = os.getenv('MAILGUN_SENDER_EMAIL', f"mailgun@{domain}")
    
    response = requests.post(
        f"https://api.mailgun.net/v3/{domain}/messages",
        auth=("api", api_key),
        data={"from": sender_email,
              "to": [to_email],
              "subject": "Password Reset Request",
              "text": f"Your password reset token is: {reset_token}"})
    
    logging.info(f"Mailgun response status: {response.status_code}")
    logging.info(f"Mailgun response body: {response.text}")
    
    return response

def generate_password_reset_token(email):
    return s.dumps(email, salt=SECURITY_PASSWORD_SALT)

def verify_password_reset_token(token, expiration=3600):
    try:
        email = s.loads(token, salt=SECURITY_PASSWORD_SALT, max_age=expiration)
    except Exception as e:
        logging.error(f"Error verifying token: {e}")
        return None
    return email
