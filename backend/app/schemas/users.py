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

class TokenInfoResponse(BaseModel):
    accessToken: str
    tokenType: str

class TokenPayload(BaseModel):
    uid: Union[str, None] = None