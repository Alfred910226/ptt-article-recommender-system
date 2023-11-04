from typing import Any, Annotated
from datetime import datetime, timedelta
import os

from fastapi import APIRouter, status, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from cassandra.cqlengine.management import sync_table
from cassandra.cqlengine import connection
from jose import JWSError, ExpiredSignatureError

from app.utils.encryptor import Hasher, Token
from app.schemas.users import UserCreate, UserCreatedResponse, UserInfo, TokenInfoResponse, TokenPayload
from app.models.users import User 

router = APIRouter(
    prefix="/user",
    tags=["user"]
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

@router.on_event("startup")
async def create_table():
    connection.setup(['cassandra'], "ptt", port=9042, protocol_version=3)
    sync_table(User)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials!",
        headers={"WWW-Authenticate": "Bearer"}
    )
    try:
        payload = Token.decode_token(token)
        uid: str = payload.get('uid')
        if uid is None:
            raise credentials_exception
        token_payload = TokenPayload(uid=uid)

    except JWSError:
        raise credentials_exception
    
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token Expired!",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    user_info = User.objects.filter(id=token_payload.uid).allow_filtering().first()

    if user_info is None:
        raise credentials_exception
    return dict(id=user_info.id, email=user_info.email, created_at=user_info.created_at, is_verified=True)

async def get_current_active_user(current_user: UserInfo = Depends(get_current_user)):
    if current_user.get('is_verified') is False:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    return current_user

@router.post("/signup/", status_code=status.HTTP_201_CREATED, response_model=UserCreatedResponse)
async def signup(user: UserCreate) -> Any:
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
                "createdAt": resp.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                "isVerified": False
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
    
@router.post("/login", response_model=TokenInfoResponse)
async def login(from_data: OAuth2PasswordRequestForm = Depends()):
    user_info = User.objects.filter(email=from_data.username).allow_filtering().first()
    if user_info is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect username!"
        )
    if not Hasher.verify_password(from_data.password, user_info.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect password!"
        )

    expires_hours = os.getenv('ACCESS_TOKEN_EXPIRES_HOURS')
    access_token_expires = timedelta(hours=int(expires_hours))
    access_token = Token.get_access_token(
        data={"uid": user_info.id.__str__()},
        expires_delta=access_token_expires
    )
    
    return {
        "accessToken": access_token,
        "tokenType": "bearer"
    }

@router.post("/logout", response_model=TokenInfoResponse)
async def logout(token: str = Depends(oauth2_scheme)):
    return None

@router.post("/items")
async def get_item(current_user: UserInfo = Depends(get_current_active_user)): #For authentication testing
    return current_user


    