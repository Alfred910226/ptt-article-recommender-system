from typing import Dict, Union
from pydantic import BaseModel, EmailStr

class UserCreate(BaseModel):
    email: EmailStr
    password: str

class UserInfo(BaseModel):
    id: str
    email: EmailStr
    created_at: str
    is_verified: bool

class UserInfoResponse(BaseModel):
    id: str
    email: EmailStr
    createdAt: str
    isVerified: bool

class ResponseBase(BaseModel):
    message: str

class UserCreatedResponse(ResponseBase):
    details: UserInfoResponse

class AccessTokenInfoResponse(BaseModel):
    accessToken: str
    tokenType: str

class AccessToken(BaseModel):
    uid: Union[str, None] = None

class EmailVerificationToken(BaseModel):
    uid: Union[str, None]
    usage: Union[str, None] = 'email-verification'
    exp: Union[int, None] 

class Email(BaseModel):
    email: EmailStr

class ResetToNewPassword(BaseModel):
    new_password: str

class PasswordResetToken(BaseModel):
    uid: str
    email: EmailStr
    usage: str = 'password-reset'
    exp: int
