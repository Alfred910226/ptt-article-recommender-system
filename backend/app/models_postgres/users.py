import uuid

from sqlalchemy import Column, Integer, String, Uuid, DateTime, Boolean, text
from sqlalchemy.sql import func

from app.database import Base


class Users(Base):
    __tablename__ = "users"

    uid = Column(Uuid, default = uuid.uuid4, primary_key = True)
    email = Column(String, primary_key = True)
    password = Column(String)
    created_at = Column(DateTime, server_default = func.now())
    is_verified = Column(Boolean, default=False)