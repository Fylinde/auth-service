import re
from passlib.context import CryptContext
from password_validator import PasswordValidator

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Validate password using custom rules
def validate_password(password: str) -> bool:
    schema = PasswordValidator()
    schema \
        .min(8) \
        .max(100) \
        .has().uppercase() \
        .has().lowercase() \
        .has().digits() \
        .has().no().spaces() \
        .has().symbols()

    return schema.validate(password)

# Hash the password
def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

# Verify password against the hash
def verify_password(password: str, hashed_password: str) -> bool:
    return pwd_context.verify(password, hashed_password)
