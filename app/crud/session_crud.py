from sqlalchemy.orm import Session
from app.models.session import Session as SessionModel
from app.schemas.session_schemas import SessionCreate

def create_session(db: Session, session: SessionCreate):
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
    return db.query(SessionModel).filter(SessionModel.session_token == session_token).first()

def delete_session(db: Session, session_id: int):
    db_session = db.query(SessionModel).filter(SessionModel.id == session_id).first()
    if db_session:
        db.delete(db_session)
        db.commit()
        return True
    return False
