
from app.database import SessionLocal
from fastapi.security import OAuth2PasswordBearer


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# dependencies.py

# This creates an OAuth2PasswordBearer instance, which is a dependency that extracts the token from the "Authorization" header
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")
