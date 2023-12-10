from uuid import UUID
from datetime import datetime

from pydantic import BaseModel, EmailStr, SecretStr

class UserInfoBase(BaseModel):
    username: str
    email: EmailStr

class UserInfo(UserInfoBase):
    uid: UUID
    password: SecretStr
    created_at: datetime
    updated_at: datetime
    is_verified: bool
    access_token: str
    access_token: str
    class Config:
        orm_mode: True

class TokenInfo(BaseModel):
    uid: UUID
    token_usage: str
    exp: int