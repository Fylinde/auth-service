from sqlalchemy.orm import Session
from app.models.session import SessionModel  # Updated import to use SessionModel directly
from app.schemas.session_schemas import SessionCreate
import logging


def create_session(db: Session, session: SessionCreate):
    """
    Create a new session for a logged-in user.
    """
    # Create the session using the SessionModel with session attributes
    db_session = SessionModel(
        user_id=session.user_id,
        session_token=session.session_token,
        expires_at=session.expires_at,
        is_valid=session.is_valid
    )
    db.add(db_session)
    db.commit()
    db.refresh(db_session)
    return db_session


def get_session_by_token(db: Session, session_token: str):
    """
    Retrieve a session by session token.
    """
    return db.query(SessionModel).filter(SessionModel.session_token == session_token).first()




def delete_session_by_token(db: Session, session_token: str):
    logging.info(f"Searching for session with token: {session_token}")
    session = db.query(SessionModel).filter(SessionModel.session_token == session_token).first()
    if session:
        db.delete(session)
        db.commit()
        logging.info("Session deleted successfully.")
        return True
    logging.info("Session not found.")
    return False



def invalidate_session(db: Session, session_token: str):
    """
    Invalidate a session by marking it as invalid using the session token.
    """
    session = db.query(SessionModel).filter(SessionModel.session_token == session_token).first()
    if session:
        session.is_valid = False
        db.commit()
        return session
    return None
