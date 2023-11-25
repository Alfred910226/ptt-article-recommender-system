from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models_postgres.users import Users
from app.schemas.users import CreateUser, Email


def get_user_info_by_email(db: Session, email: Email):
    return db.query(Users).filter(Users.email == email).first()

def get_user_info_by_uid(db: Session, uid: str):
    return db.query(Users).filter(Users.uid == uid).first()

def create_user(db: Session, user: CreateUser):
    user = Users(email = user.email, password = user.password)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

def activate_user_account(db: Session, uid: str):
    user = db.query(Users).filter(Users.uid == uid).first()
    user.is_verified = True
    db.commit()
    db.refresh(user)
    return user

def update_user_password(db: Session, uid: str, password: str):
    user = db.query(Users).filter(Users.uid == uid).first()
    user.password = password
    db.commit()
    db.refresh(user)
    return user



