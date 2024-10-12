from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
is_valid = pwd_context.verify("TestPassword123!", "$2b$12$6apt3/Uct.xfpQYFt8v/HeHdszg9CEH1S22JcU7mChkl7vjnLzlai")
print(is_valid)
