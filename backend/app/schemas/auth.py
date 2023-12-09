from uuid import UUID
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, SecretStr, Field

class UserInfoBase(BaseModel):
    username: str
    email: EmailStr

class UserInfoCreate(UserInfoBase):
    password: SecretStr

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

class UserInfoValidated(BaseModel):
    uid: UUID
    username: str
    email: EmailStr

class FormData(BaseModel):
    email: EmailStr
    password: SecretStr

class TokenInfo(BaseModel):
    uid: UUID
    token_usage: str
    exp: int

class Tokens(BaseModel):
    access_token: Optional[str]
    refresh_token: Optional[str]

class EmailVerification(BaseModel):
    email_verification_token: str
    verification_code: str

class ForgotPassword(BaseModel):
    email: EmailStr

class ChangePassword(BaseModel):
    change_password_token: Optional[str]
    password: SecretStr

class CheckUsernameExists(BaseModel):
    username: str
    


