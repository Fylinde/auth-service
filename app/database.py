from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from app.config import settings
import os

# Base class for models
BaseModel = declarative_base()

# Main production database URL
SQLALCHEMY_DATABASE_URL = settings.DATABASE_URL

# Define a test database URL (set this URL in your environment variables)
TEST_SQLALCHEMY_DATABASE_URL = os.getenv("TEST_DATABASE_URL", "postgresql://test_user:test_password@localhost:5432/test_db")

# Conditionally select the correct URL based on the environment
database_url = TEST_SQLALCHEMY_DATABASE_URL if os.getenv("TESTING") else SQLALCHEMY_DATABASE_URL

# Create engine for the selected database
engine = create_engine(database_url)

# Regular Session for production use
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# For testing purposes, use this session
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=create_engine(TEST_SQLALCHEMY_DATABASE_URL))

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
