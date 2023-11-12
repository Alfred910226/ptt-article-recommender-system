from typing import Any, Annotated
from datetime import datetime, timedelta
import os

from fastapi import APIRouter, status, HTTPException, Depends, Response, Header, BackgroundTasks, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from cassandra.cqlengine.management import sync_table
from cassandra.cqlengine import connection
from jose import JWTError, ExpiredSignatureError

from app.utils.encryptor import Hasher, Token
from app.schemas.users import UserCreate, UserCreatedResponse, UserInfo, AccessTokenInfoResponse, AccessToken, EmailVerificationToken, ResetToNewPassword, Email, PasswordResetToken
from app.models.users import User, TokenRevoked
from app.utils.email import Mail

router = APIRouter(
    prefix="/user",
    tags=["user"]
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

@router.on_event("startup")
async def create_table():
    connection.setup(['cassandra'], "article_express", port=9042, protocol_version=3)
    sync_table(User)
    sync_table(TokenRevoked)

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
        token_payload = AccessToken(uid=uid)

    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token Expired!",
            headers={"WWW-Authenticate": "Bearer"}
        )

    except JWTError:
        raise credentials_exception
    
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
async def signup(user: UserCreate, background_tasks: BackgroundTasks) -> Any:
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
        access_token = Token.get_token(
            data={"uid": resp.uid.__str__(), "usage": "email-verification"}, 
            expires_delta=timedelta(hours=1)
        )

        body = dict(
            subject="Verify your email address.",
            token=access_token
        )
        background_tasks.add_task(Mail.verification_email, recipient=resp.email, body=body)
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

@router.get("/email-verify/")
async def email_verification(token: str):
    """
    decode email verification token
    """

    token_revoked = TokenRevoked.objects.filter(token=token).allow_filtering().first()

    if token_revoked:
        return HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token has been utilized!"
        )
    
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
        
        token_payload = EmailVerificationToken(uid=uid, usage=usage, exp=exp)

    except ExpiredSignatureError:
        return HTTPException(
            status_code=status.HTTP_406_NOT_ACCEPTABLE,
            detail="Token for email verification has expired!"
        )

    except JWTError:
        raise credentials_exception
    
    """
    query user info from database
    """
    user_info = User.objects.filter(uid=token_payload.uid).allow_filtering().first()

    if user_info:
        User.objects.filter(uid=user_info.uid, email=user_info.email).allow_filtering().update(is_verified=True)
        token_revoked_ttl: int = (exp - datetime.now().timestamp()).__int__()
        if token_revoked_ttl > 0:
            TokenRevoked.objects.ttl(token_revoked_ttl).create(token=token, uid=user_info.uid, created_at=datetime.now())
        return HTTPException(
            status_code=status.HTTP_202_ACCEPTED,
            detail="Email verification successful!"
        )
    else:
        return HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="User with email {email} does not exist!".format(email=user_info.email)
        )
    
@router.post("/resend-verification-email")
async def resend_email_verification(user_email: Email, background_tasks: BackgroundTasks):
    user_info = User.objects.filter(email=user_email.email).allow_filtering().first()
    if user_info is None:
        return HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Your email address has not been registered as an account!"
        )
    elif user_info.is_verified == True:
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Your email address has already been verified!"
        )
    else:
        access_token = Token.get_token(
            data={"uid": user_info.uid.__str__(), "usage": "email-verification"}, 
            expires_delta=timedelta(hours=1)
        )
        body = dict(
            subject="Verify your email address",
            token=access_token
        )
        background_tasks.add_task(Mail.verification_email, recipient=user_info.email, body=body)
        return dict(
            detail="Verification email has been sent to your registered email address!"
        )

@router.post("/forgot-password")
async def send_password_reset_email(email: Email):
    user_info = User.objects.filter(email=email.email).allow_filtering().first()
    if user_info is None:
        return HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Your email address has not been registered as an account!"
        )
    elif user_info.is_verified == True:
        access_token = Token.get_token(
            data={"uid": user_info.uid.__str__(), "email": user_info.email, "usage": "password-reset"}, 
            expires_delta=timedelta(hours=1)
        )
        return dict(
            access_token=access_token,
            token_type="bearer",
            detail="Password reset email has been sent to your registered email address!"
        )
        
@router.put("/reset-password")
async def reset_to_new_password(input: ResetToNewPassword, Authorization: Annotated[list[str] | None, Header()] = None):
    """
    input
    1. new password
    2. access token
    """
    import re
    token = re.search(r'Bearer\s+(\S+)', Authorization[0]).group(1)

    token_revoked = TokenRevoked.objects.filter(token=token).allow_filtering().first()

    if token_revoked:
        return HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token has been utilized!"
        )

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid token for password reset!",
    )

    try:
        payload = Token.decode_token(token)
        uid: str = payload.get('uid')
        email: str = payload.get('email')
        usage: str = payload.get('usage')
        exp: int = payload.get('exp')
        if uid is None:
            raise credentials_exception
        if usage is None or usage != "password-reset":
            raise credentials_exception
        
        token_payload = PasswordResetToken(uid=uid, email=email, usage=usage, exp=exp)

    except ExpiredSignatureError:
        return HTTPException(
            status_code=status.HTTP_406_NOT_ACCEPTABLE,
            detail="Token for password reset has expired!"
        )

    except JWTError:
        raise credentials_exception

    user_info = User.objects.filter(uid=token_payload.uid, email=token_payload.email).allow_filtering().first()

    if user_info:
        User.objects.filter(uid=token_payload.uid, email=token_payload.email).allow_filtering().update(password=Hasher.get_password_hash(input.new_password))
        token_revoked_ttl: int = (exp - datetime.now().timestamp()).__int__()
        if token_revoked_ttl > 0:
            TokenRevoked.objects.ttl(token_revoked_ttl).create(token=token, uid=user_info.uid, created_at=datetime.now())

        expires_hours = os.getenv('ACCESS_TOKEN_EXPIRES_HOURS')
        access_token_expires = timedelta(hours=int(expires_hours))
        access_token = Token.get_token(
            data={"uid": user_info.uid.__str__()},
            expires_delta=access_token_expires
        )

        return dict(
            access_token=access_token,
            token_type="bearer",
            detail="Password has been successfully reset!"
        )
    
    else:
        return HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token for password reset!",
        )

@router.post("/logout", response_model=AccessTokenInfoResponse)
async def logout(token: str = Depends(oauth2_scheme)):
    return None

@router.get("/auth-testing")
async def auth_testing(current_user: UserInfo = Depends(get_current_active_user)): #For authentication testing
    return current_user

@router.get("/email-testing")
async def email_testing(background_tasks: BackgroundTasks):
    return None