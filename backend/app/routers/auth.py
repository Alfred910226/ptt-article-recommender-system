

from fastapi import APIRouter, Depends
from fastapi.security import OAuth2PasswordBearer

from app.models_postgres import users
from app.database import engine
from app.database import SessionLocal
from app.schemas.auth import UserInfoCreate, FormData, Tokens, UserInfoValidated, EmailVerification, ForgotPassword, ChangePassword, CheckUsernameExists
from app.services.auth import AuthService
from app.utils.service_result import handle_result

users.Base.metadata.create_all(bind=engine)

router = APIRouter(
    prefix = "/auth",
    tags = ["auth"]
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='login')

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def validate_current_user(access_token: oauth2_scheme = Depends(), db: get_db = Depends()):
    result = AuthService(db).validate_current_user(access_token)
    return handle_result(result)

@router.post("/signup")
async def create_account(user: UserInfoCreate, db: get_db = Depends()):
    result = AuthService(db).create_account(user)
    return handle_result(result)

@router.post("/login")
async def login_account(form_data: FormData, db: get_db = Depends()):
    result = AuthService(db).login_account(form_data)
    return handle_result(result)

@router.post("/logout")
async def logout_account(db: get_db = Depends(), user_info: validate_current_user = Depends()):
    user_info = UserInfoValidated(**user_info)
    result = AuthService(db).logout_account(user_info)
    return handle_result(result)

@router.post("/refresh-token")
async def get_refresh_token(token: Tokens, db: get_db = Depends()):
    result = AuthService(db).get_refresh_token(token)
    return handle_result(result)

@router.post("/email-verification")
async def email_verification(verification_info: EmailVerification, db: get_db = Depends()):
    result = AuthService(db).email_verification(verification_info)
    return handle_result(result)

@router.post("/resend-email-verification")
async def resend_email_verifiaction(db: get_db = Depends(), user_info: validate_current_user = Depends()):
    user_info = UserInfoValidated(**user_info)
    result = AuthService(db).resend_email_verification(user_info)
    return handle_result(result)

@router.post("/forgot-password")
async def forgot_password(form_data: ForgotPassword, db: get_db = Depends()):
    result = AuthService(db).forgot_password(form_data)
    return handle_result(result)

@router.put("/forgot-password")
async def change_password(form_data: ChangePassword, db: get_db = Depends()):
    result = AuthService(db).change_password(form_data)
    return handle_result(result)

@router.post("/check-username")
async def check_username_exists(form_data: CheckUsernameExists, db: get_db = Depends()):
    result = AuthService(db).check_username_exists(form_data)
    return handle_result(result)

@router.get("/testing")
async def testing( data: validate_current_user = Depends()):
    return data
