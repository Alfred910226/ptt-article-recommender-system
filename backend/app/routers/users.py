from typing import Any, Annotated
from datetime import datetime, timedelta
import os

from fastapi import APIRouter, status, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from cassandra.cqlengine.management import sync_table
from cassandra.cqlengine import connection
from jose import JWTError, ExpiredSignatureError

from app.utils.encryptor import Hasher, Token
from app.schemas.users import UserCreate, UserCreatedResponse, UserInfo, AccessTokenInfoResponse, AccessTokenPayload, EmailVerificationTokenPayload
from app.models.users import User, AuthenticatedEmailVerificationToken

router = APIRouter(
    prefix="/user",
    tags=["user"]
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

@router.on_event("startup")
async def create_table():
    connection.setup(['cassandra'], "ptt", port=9042, protocol_version=3)
    sync_table(User)
    sync_table(AuthenticatedEmailVerificationToken)

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
        token_payload = AccessTokenPayload(uid=uid)

    except JWTError:
        raise credentials_exception
    
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token Expired!",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    user_info = User.objects.filter(uid=token_payload.uid).allow_filtering().first()

    if user_info is None:
        raise credentials_exception
    return dict(uid=user_info.uid, email=user_info.email, created_at=user_info.created_at, is_verified=user_info.is_verified)

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
        create user profile
        """
        resp = User.create(email=user.email, 
                           password=Hasher.get_password_hash(user.password), 
                           created_at=datetime.now())
        """
        email verification
        """
        email_verification_token = Token.get_token(
            data={"uid": resp.uid.__str__(), "usage": "email-verification"}, 
            expires_delta=timedelta(hours=1)
        )
        print(email_verification_token)
        """
        ## this email_verification_token send by email ##
        """

        return {
            "message": "User registration successful",
            "details": {
                "id": resp.uid.__str__(),
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
    
@router.post("/login", response_model=AccessTokenInfoResponse)
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
    access_token = Token.get_token(
        data={"uid": user_info.uid.__str__()},
        expires_delta=access_token_expires
    )
    
    return {
        "accessToken": access_token,
        "tokenType": "bearer"
    }

@router.post("/email-verify/")
async def email_verification(token: str):
    """
    decode email verification token
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid token for email verification!",
    )
    try:
        payload = Token.decode_token(token)
        uid: str = payload.get('uid')
        usage: str = payload.get('usage')
        exp: int = payload.get('exp')
        if uid is None:
            raise credentials_exception
        if usage is None or usage != "email-verification":
            raise credentials_exception
        
        token_payload = EmailVerificationTokenPayload(uid=uid, usage=usage, exp=exp)

    except JWTError:
        raise credentials_exception
    
    except ExpiredSignatureError:
        return HTTPException(
            status_code=status.HTTP_406_NOT_ACCEPTABLE,
            detail="Token for email verification has expired!"
        )

    """
    query user info from database
    """
    token_info = AuthenticatedEmailVerificationToken.objects.filter(token=token).allow_filtering().first()

    if token_info is not None:
        return HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token has been utilized!"
        )

    user_info = User.objects.filter(uid=token_payload.uid).allow_filtering().first()

    if user_info:
        User.objects.filter(uid=user_info.uid, email=user_info.email).allow_filtering().update(is_verified=True)
        authenticated_token_ttl: int = (exp - datetime.now().timestamp()).__int__()
        if authenticated_token_ttl > 0:
            AuthenticatedEmailVerificationToken.objects.ttl(authenticated_token_ttl).create(token=token, uid=user_info.uid, created_at=datetime.now())
        return HTTPException(
            status_code=status.HTTP_202_ACCEPTED,
            detail="Email verification successful!"
        )
    else:
        return HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="User with email {email} does not exist!".format(email=user_info.email)
        )

@router.post("/logout", response_model=AccessTokenInfoResponse)
async def logout(token: str = Depends(oauth2_scheme)):
    return None

@router.get("/auth-testing")
async def auth_testing(current_user: UserInfo = Depends(get_current_active_user)): #For authentication testing
    return current_user


    