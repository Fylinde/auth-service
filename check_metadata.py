from app.database import BaseModel
from app.models.user import UserModel
from app.models.admin import AdminModel
from app.models.vendor import VendorModel

print(BaseModel.metadata.tables)  # This should now show your tables


print(BaseModel.metadata.tables)  # This should list all the tables in your models
