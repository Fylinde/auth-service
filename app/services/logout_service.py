
from app.utils.rabbitmq import RabbitMQConnection
from fastapi import HTTPException
from app.crud.session_crud import delete_session_by_token  # Assuming this exists to handle session invalidation
from sqlalchemy.orm import Session

# RabbitMQ setup for publishing events
rabbitmq = RabbitMQConnection(exchange_name="auth_events", exchange_type="fanout")



def logout_user_service(db: Session, session_token: str):
    # Call CRUD to delete the session
    success = delete_session_by_token(db, session_token)
    if not success:
        raise HTTPException(status_code=404, detail="Session not found or already logged out")
    return {"message": "Logout successful"}