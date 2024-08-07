import re
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def validate_password(password: str) -> bool:
    # Minimum length 8 characters
    if len(password) < 8:
        return False
    # At least one uppercase letter
    if not re.search(r'[A-Z]', password):
        return False
    # At least one lowercase letter
    if not re.search(r'[a-z]', password):
        return False
    # At least one digit
    if not re.search(r'\d', password):
        return False
    # At least one special character
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False

    return True

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)
