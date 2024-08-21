from password_validator import PasswordValidator
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def validate_password(password: str) -> bool:
    schema = PasswordValidator()
    schema \
        .min(8) \
        .max(100) \
        .has().uppercase() \
        .has().lowercase() \
        .has().digits() \
        .has().no().spaces()
    
    return schema.validate(password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)
