from typing import Dict, Union
from pydantic import BaseModel, EmailStr

class UserInfo(BaseModel):
    id: str
    email: EmailStr
    created_at: str
    is_verified: bool

class CreateUser(BaseModel):
    email: EmailStr
    password: str

class CreateUserResponse(BaseModel):
    message: str
    details: UserInfo

class AccessToken(BaseModel):
    uid: Union[str, None] = None

class AccessTokenResponse(BaseModel):
    access_token: str
    token_type: str

class ResendVerificationEmailResponse(BaseModel):
    detail: str

class SendPasswordResetEmailResponse(BaseModel):
    detail: str

class EmailVerificationToken(BaseModel):
    uid: Union[str, None]
    usage: str = 'email-verification'
    exp: Union[int, None] 

class Email(BaseModel):
    email: EmailStr

class ResetToNewPassword(BaseModel):
    new_password: str

class ResetToNewPasswordResponse(BaseModel):
    detail: str

class PasswordResetToken(BaseModel):
    uid: str
    email: EmailStr
    usage: str = 'password-reset'
    exp: int
