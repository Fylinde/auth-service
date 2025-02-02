# test_models.py

from app.database import BaseModel, engine, TestingSessionLocal  # Correct import for BaseModel
from app.models import UserModel, SellerModel, GroupModel, PermissionModel, CustomerNoteModel, CustomerEventModel, StaffNotificationRecipientModel, AddressModel
import pytest

from app.models import (
    UserModel,
    Session,
    SellerModel,
    GroupModel,
    PermissionModel,
    CustomerNoteModel,
    CustomerEventModel,
    StaffNotificationRecipientModel,
    AddressModel,
)
from app.database import TestingSessionLocal, engine
from sqlalchemy.exc import IntegrityError


@pytest.fixture(scope="function")
def db_session():
    # Create tables for the test
    BaseModel.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    yield session
    session.close()
    BaseModel.metadata.drop_all(bind=engine)


def test_create_user(db_session):
    user = UserModel(username="testuser", email="test@example.com", hashed_password="hashedpassword")
    db_session.add(user)
    db_session.commit()

    assert user.id is not None
    assert user.username == "testuser"
    assert user.email == "test@example.com"


#def test_create_admin(db_session):
 #   admin = AdminModel(username="adminuser", email="admin@example.com", hashed_password="hashedpassword")
 #   db_session.add(admin)
 #   db_session.commit()

 #   assert admin.id is not None
 #   assert admin.username == "adminuser"
 #   assert admin.email == "admin@example.com"
 #   assert admin.role == "admin"


def test_create_vendor(db_session):
    seller = SellerModel(name="Test Vendor", email="vendor@example.com", hashed_password="hashedpassword")
    db_session.add(seller)
    db_session.commit()

    assert seller.id is not None
    assert seller.name == "Test Vendor"
    assert seller.email == "vendor@example.com"


def test_create_group(db_session):
    group = GroupModel(name="Test Group")
    db_session.add(group)
    db_session.commit()

    assert group.id is not None
    assert group.name == "Test Group"


def test_create_permission(db_session):
    permission = PermissionModel(name="test_permission")
    db_session.add(permission)
    db_session.commit()

    assert permission.id is not None
    assert permission.name == "test_permission"


def test_create_customer_note(db_session):
    note = CustomerNoteModel(content="This is a note", customer_id=1)
    db_session.add(note)
    db_session.commit()

    assert note.id is not None
    assert note.content == "This is a note"
    assert note.customer_id == 1


def test_create_customer_event(db_session):
    event = CustomerEventModel(type="order_placed", parameters="{}", customer_id=1)
    db_session.add(event)
    db_session.commit()

    assert event.id is not None
    assert event.type == "order_placed"
    assert event.customer_id == 1


def test_create_staff_notification(db_session):
    staff_notification = StaffNotificationRecipientModel(staff_email="staff@example.com", active=True)
    db_session.add(staff_notification)
    db_session.commit()

    assert staff_notification.id is not None
    assert staff_notification.staff_email == "staff@example.com"
    assert staff_notification.active is True


def test_create_address(db_session):
    address = AddressModel(first_name="John", last_name="Doe", country="US", postal_code="12345")
    db_session.add(address)
    db_session.commit()

    assert address.id is not None
    assert address.first_name == "John"
    assert address.last_name == "Doe"
    assert address.country == "US"
