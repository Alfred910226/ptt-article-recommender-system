import uuid

from sqlalchemy import Column, Integer, String, Uuid, DateTime, Boolean, text
from sqlalchemy.sql import func

from app.database import Base


class Users(Base):
    __tablename__ = "users"

    uid = Column(Uuid, default=uuid.uuid4, primary_key=True, nullable=False)
    email = Column(String, unique=True,  nullable=False)
    username = Column(String, unique=True,  nullable=False)
    password = Column(String,  nullable=False)
    created_at = Column(DateTime, server_default=func.now(),  nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), server_onupdate=func.now(),  nullable=False)
    is_verified = Column(Boolean, default=False,  nullable=False)
    access_token = Column(String)
    refresh_token = Column(String)