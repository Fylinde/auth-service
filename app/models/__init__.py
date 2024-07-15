from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

# Ensure you also import all your models here to register them with SQLAlchemy
from .user import User  # example model, adjust according to your actual models
