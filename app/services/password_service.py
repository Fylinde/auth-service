
from app.utils.rabbitmq import RabbitMQConnection
from fastapi import HTTPException
import os
from app.crud.session_crud import delete_session_by_token
from sqlalchemy.orm import Session


# RabbitMQ setup for publishing events
rabbitmq = RabbitMQConnection(exchange_name="auth_events", exchange_type="fanout")

USER_SERVICE_URL = os.getenv("USER_SERVICE_URL", "http://user-service/api/users")

def logout_user_service(db: Session, token: str):
    # Call CRUD to delete the session
    success = delete_session_by_token(db, token)
    if not success:
        raise HTTPException(status_code=404, detail="Session not found or already logged out")
    return {"message": "Logout successful"}