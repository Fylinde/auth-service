from sqlalchemy import Column, Integer, String, Float
from app.database import BaseModel

class VendorModel(BaseModel):
    __tablename__ = 'vendors'

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    description = Column(String, nullable=True)
    rating = Column(Float, nullable=True)
    hashed_password = Column(String, nullable=False)  # Add this line
