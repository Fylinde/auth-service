from app.models.user import UserModel
from sqlalchemy import Column, Integer, String, Float, ForeignKey


class AdminModel(UserModel):
    __tablename__ = "admins"

    # Inherit all fields from UserModel, add admin-specific fields here if needed
    # Example:
    # additional_permissions = Column(ARRAY(String), nullable=True)
    id = Column(Integer, ForeignKey('users.id'), primary_key=True)
    # Override the default role to "admin"
    role = Column(String, default="admin")
