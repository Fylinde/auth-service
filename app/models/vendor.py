from sqlalchemy import Column, Integer, String, Float
from app.database import BaseModel

class VendorModel(BaseModel):
    __tablename__ = 'vendors'

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False, index=True)  # Limit name to 100 characters, ensure not null
    email = Column(String(100), nullable=False, unique=True, index=True)  # Limit email to 100 characters, unique and not null
    description = Column(String(255))  # Limit description to 255 characters
    rating = Column(Integer, nullable=True)  # Rating is an integer, optional field
    profile_picture = Column(String(255), nullable=True)  # Limit profile picture URL to 255 characters
    preferences = Column(String(255), nullable=True)  # Limit preferences JSON string to 255 characters
    hashed_password = Column(String(255), nullable=False)  # Ensure hashed password field is long enough and not null
