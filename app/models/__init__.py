# app/models/__init__.py

#from sqlalchemy.ext.declarative import declarative_base
#from app.models.session import Session
#from app.models import User as UserModel  # Importing UserModel consistently
#from app.database import Base


#Base = declarative_base()

# Ensure you also import all your models here to register them with SQLAlchemy
#from .user import User  # example model, adjust according to your actual models

#from app.models.user import User as UserModel  # Ensure UserModel is imported consistently
from .session import Session
from app.database import BaseModel
from .admin import AdminModel
from .user import UserModel
from .vendor import VendorModel

__all__ = ["Session", "BaseModel", "AdminModel", "UserModel", "VendorModel" ]

