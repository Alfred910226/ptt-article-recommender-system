from typing import Dict
from pydantic import BaseModel, EmailStr

class UserCreate(BaseModel):
    email: EmailStr
    password: str

class UserInfo(BaseModel):
    id: str
    email: EmailStr
    created_at: str

class ResponseBase(BaseModel):
    message: str

class UserCreatedResponse(ResponseBase):
    details: UserInfo