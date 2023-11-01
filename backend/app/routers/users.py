from typing import Any

from fastapi import APIRouter, status, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from cassandra.cqlengine.management import sync_table
from cassandra.cqlengine import connection
from datetime import datetime

from app.utils.encryptor import Hasher
from app.schemas.users import UserCreate, UserCreatedResponse
from app.models.users import User 

router = APIRouter(
    prefix="/user",
    tags=["user"]
)

@router.on_event("startup")
async def create_table():
    connection.setup(['cassandra'], "ptt", port=9042, protocol_version=3)
    sync_table(User)

@router.post("/signup/", status_code=status.HTTP_201_CREATED, response_model=UserCreatedResponse)
async def create_user(user: UserCreate) -> Any:
    user_info = User.objects.filter(email=user.email).allow_filtering().first() # 確認資料使用者是否存在
    if user_info is None:
        """
        1. hashing password
        2. insert hashing password to database
        3. return account created message
        """
        resp = User.create(email=user.email, 
                    password=Hasher.get_password_hash(user.password), 
                    created_at=datetime.now())
        
        return {
            "message": "User registration successful",
            "details": {
                "id": resp.id.__str__(),
                "email": resp.email,
                "created_at": resp.created_at.strftime('%Y-%m-%d %H:%M:%S')
            }
        }
    else:
        """
        1. raise account exist error
        """
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email is already registered!"
        )