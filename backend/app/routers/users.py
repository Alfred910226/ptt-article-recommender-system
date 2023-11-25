from typing import Any, Annotated
from datetime import datetime, timedelta
import os

from fastapi import APIRouter, status, HTTPException, Depends, Header, BackgroundTasks, Request, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from jose import JWTError, ExpiredSignatureError

from app.utils.encryptor import Hasher, Token
from app.schemas.users import (
    CreateUser, 
    CreateUserResponse, 
    UserInfo, 
    AccessTokenResponse,
    AccessToken, 
    ResendVerificationEmailResponse, 
    SendPasswordResetEmailResponse, 
    EmailVerificationToken, 
    EmailVerificationResponse,
    ResetToNewPassword, 
    ResetToNewPasswordResponse, 
    Email, 
    PasswordResetToken,
    LogoutResponse
)
from app.crud.users import (
    get_user_info_by_email,
    get_user_info_by_uid,
    create_user,
    activate_user_account,
    update_user_password
)

from app.models_postgres import users
from app.models_cassandra.users import TokenRevoked
from app.database import engine
from app.database import SessionLocal
from app.utils.email import Mail
from app.redis.base import r

users.Base.metadata.create_all(bind=engine)

router = APIRouter(
    prefix = "/user",
    tags = ["user"]
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl = "login")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> UserInfo:
    credentials_exception = HTTPException(
        status_code =status.HTTP_401_UNAUTHORIZED,
        detail = "Could not validate credentials!",
        headers = {"WWW-Authenticate": "Bearer"}
    )
    try:
        payload = Token.decode_token(token)
        uid: str = payload.get('uid')
        if uid is None:
            raise credentials_exception
        token_payload = AccessToken(uid = uid)

    except ExpiredSignatureError:
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail = "Token Expired!",
            headers = {"WWW-Authenticate": "Bearer"}
        )

    except JWTError:
        raise credentials_exception

    user_info = get_user_info_by_uid(db = db, uid = token_payload.uid)
    print(user_info)

    if user_info is None:
        raise credentials_exception
    
    # if user_info.logout is True:
    #     raise HTTPException(
    #         status_code=status.HTTP_205_RESET_CONTENT,
    #         detail="The account has been logged out. Please login again!",
    #         headers = {"WWW-Authenticate": "Bearer"}
    #     )

    return dict(
        uid = user_info.uid, 
        email = user_info.email, 
        created_at = user_info.created_at, 
        is_verified = user_info.is_verified
    )

async def get_current_active_user(current_user: UserInfo = Depends(get_current_user)) -> UserInfo:
    if current_user.get('is_verified') is False:
        raise HTTPException(
            status_code = status.HTTP_400_BAD_REQUEST,
            detail = "Inactive user!"
        )
    return current_user

@router.post("/signup/", status_code = status.HTTP_201_CREATED, response_model = CreateUserResponse)
async def signup(user: CreateUser, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    
    user_info = get_user_info_by_email( # 確認資料使用者是否存在
        db = db, 
        email = user.email
    ) 

    if user_info is None:
        """
        create user profile
        """
        user_resp = create_user(
            db = db, 
            user = CreateUser(
                **dict(
                    email = user.email,
                password = Hasher.get_password_hash(user.password)
                )
            )
        )
        """
        email verification
        """
        access_token = Token.get_token(
            data = {
                "uid": user_resp.uid.__str__(), 
                "usage": "email-verification"
            }, 
            expires_delta = timedelta(hours=1)
        )
        body = dict(
            subject = "Verify your email address!",
            token = access_token
        )
        background_tasks.add_task(
            Mail.verification_email, 
            recipient=user.email,
            body=body
        )
        return dict(
            message = "User registration successful!",
            details = dict(
                uid = user_resp.uid.__str__(),
                email = user_resp.email,
                created_at = user_resp.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                is_verified = user_resp.is_verified
            )
        )

    else:
        """
        1. raise account exist error
        """
        raise HTTPException(
            status_code = status.HTTP_409_CONFLICT,
            detail = "Email is already registered!"
        )
    
@router.post("/login", status_code = status.HTTP_200_OK, response_model = AccessTokenResponse)
async def login(from_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):

    user_info = get_user_info_by_email(
        db = db, 
        email = from_data.username
    )

    if user_info is None:
        raise HTTPException(
            status_code = status.HTTP_400_BAD_REQUEST,
            detail = "Incorrect username!"
        )
    if not Hasher.verify_password(from_data.password, user_info.password):
        raise HTTPException(
            status_code = status.HTTP_400_BAD_REQUEST,
            detail = "Incorrect password!"
        )

    expires_hours = os.getenv('ACCESS_TOKEN_EXPIRES_HOURS')
    access_token_expires = timedelta(hours=int(expires_hours))
    access_token = Token.get_token(
        data={
            "uid": user_info.uid.__str__()
        },
        expires_delta=access_token_expires
    )

    return dict(
        access_token = access_token,
        token_type = "bearer"
    )

@router.get("/email-verify/", status_code = status.HTTP_200_OK, response_model = EmailVerificationResponse)
async def email_verification(token: str, db: Session = Depends(get_db)):
    """
    decode email verification token
    """
    token_revoked: dict = TokenRevoked.objects.filter(token = token).allow_filtering().first()

    if token_revoked:
        raise HTTPException(
            status_code = status.HTTP_403_FORBIDDEN,
            detail = "Token has been utilized!"
        )
    
    credentials_exception = HTTPException(
        status_code = status.HTTP_401_UNAUTHORIZED,
        detail = "Invalid token for email verification!",
    )
    try:
        payload: dict = Token.decode_token(token)
        uid: str = payload.get('uid')
        usage: str = payload.get('usage')
        exp: int = payload.get('exp')
        if uid is None:
            raise credentials_exception
        if usage is None or usage != "email-verification":
            raise credentials_exception
        
        token_payload = EmailVerificationToken(
            uid = uid, 
            usage = usage, 
            exp = exp
        )

    except ExpiredSignatureError:
        raise HTTPException(
            status_code = status.HTTP_406_NOT_ACCEPTABLE,
            detail = "Token for email verification has expired!"
        )

    except JWTError:
        raise credentials_exception
    
    """
    query user info from database
    """

    user_info = get_user_info_by_uid(
        db = db,
        uid = token_payload.uid
    )

    if user_info:
        activate_user_account(db = db, uid = user_info.uid)

        token_revoked_ttl: int = (exp - datetime.now().timestamp()).__int__()
        if token_revoked_ttl > 0:
            TokenRevoked.objects.ttl(token_revoked_ttl).create(token=token, uid=user_info.uid, created_at=datetime.now())
        return dict(
            detail = "Email verification successful!"
        )
    else:
        raise HTTPException(
            status_code = status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail = "User with email {email} does not exist!".format(email=user_info.email)
        )
    
@router.post("/resend-verification-email", status_code = status.HTTP_200_OK, response_model = ResendVerificationEmailResponse)
async def resend_verification_email(user_email: Email, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    if r.get(user_email.email) is not None:
        raise HTTPException(
            status_code=status.HTTP_202_ACCEPTED,
            detail="Email is being sent!"
        )

    user_info = get_user_info_by_email( # 確認資料使用者是否存在
        db = db, 
        email = user_email.email
    ) 

    if user_info is None:
        raise HTTPException(
            status_code = status.HTTP_404_NOT_FOUND,
            detail = "Your email address has not been registered as an account!"
        )
    elif user_info.is_verified == True:
        raise HTTPException(
            status_code = status.HTTP_409_CONFLICT,
            detail = "Your email address has already been verified!"
        )
    else:
        access_token: dict = Token.get_token(
            data = {
                "uid": user_info.uid.__str__(), 
                "usage": "email-verification"
            }, 
            expires_delta = timedelta(hours=1)
        )
        body = dict(
            subject = "Verify your email address",
            token = access_token
        )
        background_tasks.add_task(
            Mail.verification_email, 
            recipient = user_info.email, 
            body = body
        )
        return dict(
            detail = "Verification email has been sent to your registered email address!"
        )
    
@router.get("/forgot-password/page")
async def get_forgot_password_page(request: Request):
    templates = Jinja2Templates(
        directory = "app/templates/forgot_password"
    )
    return templates.TemplateResponse(
        "forgot_password_page.html", 
        {"request": request}
    )

@router.post("/forgot-password", status_code = status.HTTP_200_OK, response_model=SendPasswordResetEmailResponse)
async def send_password_reset_email(email: Email, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    user_info = get_user_info_by_email( # 確認資料使用者是否存在
        db = db, 
        email = email.email
    ) 
    if user_info is None:
        raise HTTPException(
            status_code = status.HTTP_404_NOT_FOUND,
            detail = "Your email address has not been registered as an account!"
        )
    elif user_info.is_verified == True:
        access_token = Token.get_token(
            data = {
                "uid": user_info.uid.__str__(), 
                "email": user_info.email, 
                "usage": "password-reset"
            }, 
            expires_delta = timedelta(hours=1)
        )

        body = dict(
            subject = "Reset password.",
            token = access_token
        )

        background_tasks.add_task(
            Mail.password_reset_email, 
            recipient = user_info.email, 
            body = body
        )

        return dict(
            detail = "Password reset email has been sent to your registered email address!"
        )

    elif user_info.is_verified == False:
        raise HTTPException(
            status_code = status.HTTP_400_BAD_REQUEST,
            detail = "Inactive user!"
        )

@router.get("/reset-password/page")
async def get_password_reset_page(token: str, request: Request, response: Response):

    token_revoked: dict = TokenRevoked.objects.filter(token=token).allow_filtering().first()

    if token_revoked:
        raise HTTPException(
            status_code = status.HTTP_403_FORBIDDEN,
            detail = "Token has been utilized!"
        )
    
    credentials_exception = HTTPException(
        status_code = status.HTTP_401_UNAUTHORIZED,
        detail = "Invalid token for password reset!",
    )

    try:
        payload: dict = Token.decode_token(token)
        uid: str = payload.get('uid')
        usage: str = payload.get('usage')
        if uid is None:
            raise credentials_exception
        if usage is None or usage != "password-reset":
            raise credentials_exception
        
    except ExpiredSignatureError:
        raise HTTPException(
            status_code = status.HTTP_406_NOT_ACCEPTABLE,
            detail = "Token for password reset has expired!"
        )
    
    except JWTError:
        raise credentials_exception

    templates = Jinja2Templates(
        directory = "app/templates/forgot_password"
    )

    Authorization = "Bearer {token}".format(
        token = token
    )
    return templates.TemplateResponse(
        "password_reset_page.html", 
        {"request": request, "Authorization": Authorization}
    )
        
@router.put("/reset-password", status_code = status.HTTP_200_OK, response_model = ResetToNewPasswordResponse)
async def reset_to_new_password(input: ResetToNewPassword, Authorization: Annotated[list[str] | None, Header()] = None, db: Session = Depends(get_db)):
    """
    input
    1. new password
    2. access token
    """
    import re
    token = re.search(r'Bearer\s+(\S+)', Authorization[0]).group(1)

    token_revoked: dict = TokenRevoked.objects.filter(token = token).allow_filtering().first()

    if token_revoked:
        raise HTTPException(
            status_code = status.HTTP_403_FORBIDDEN,
            detail = "Token has been utilized!"
        )

    credentials_exception = HTTPException(
        status_code = status.HTTP_401_UNAUTHORIZED,
        detail = "Invalid token for password reset!",
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
        
        token_payload = PasswordResetToken(
            uid = uid, 
            email = email, 
            usage = usage, 
            exp = exp
        )

    except ExpiredSignatureError:
        raise HTTPException(
            status_code = status.HTTP_406_NOT_ACCEPTABLE,
            detail = "Token for password reset has expired!"
        )

    except JWTError:
        raise credentials_exception

    user_info = get_user_info_by_uid( # 確認資料使用者是否存在
        db = db, 
        uid = token_payload.uid
    ) 

    if user_info:
        update_user_password(
            db = db,
            uid = token_payload.uid,
            password = Hasher.get_password_hash(input.new_password)
        )
        token_revoked_ttl: int = (exp - datetime.now().timestamp()).__int__()
        if token_revoked_ttl > 0:
            TokenRevoked.objects.ttl(token_revoked_ttl).create(token = token, uid = user_info.uid, created_at = datetime.now())

        """
        Add return to sign in page
        """
        return dict(
            detail = "Password has been successfully reset!"
        )
    
    else:
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail = "Invalid token for password reset!"
        )

# @router.post("/logout", response_model = LogoutResponse)
# async def logout(current_user: UserInfo = Depends(get_current_active_user)):
#     uid: str = current_user.get('uid')
#     email: str = current_user.get('email')
#     User.objects(uid = uid, email = email).update(logout=True)
#     return dict(
#         detail="Your account has been successfully logged out!"
#     )

@router.get("/auth-testing")
async def auth_testing(current_user: UserInfo = Depends(get_current_active_user)): # For authentication testing
    return current_user

