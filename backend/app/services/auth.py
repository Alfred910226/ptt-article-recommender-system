import random
import string
import os
from datetime import timedelta, datetime

from fastapi import BackgroundTasks
from jose import JWTError, ExpiredSignatureError

from app.services.main import AppService, AppCRUD
from app.schemas.auth import UserInfo, UserInfoCreate, FormData, TokenInfo, Tokens, UserInfoValidated, EmailVerification, ForgotPassword, ChangePassword, CheckUsernameExists
from app.models_postgres.users import Users
from app.utils.service_result import ServiceResult
from app.utils.app_exceptions import AppException
from app.utils.jwt import Token
from app.utils.hashing import Hasher
from app.models_cassandra.users import TokenRevoked, EmailVerificationCode
from app.utils.email import Mail

class AuthService(AppService):
    def create_account(self, user: UserInfoCreate, background_tasks: BackgroundTasks) -> ServiceResult:
        user_info = AuthCRUD(self.db).get_account_info_by_email(user.username)
        if user_info:
            return ServiceResult(AppException.UserInfoConflict({"message": "Email is already taken!"}))
        
        user_info = AuthCRUD(self.db).get_account_info_by_username(user.username)
        if user_info:
            return ServiceResult(AppException.UserInfoConflict({"message": "Username is already taken!"}))            
        
        user_updated = dict(
            username=user.username,
            email=user.email,
            password=Hasher.get_password_hash(user.password.get_secret_value())
        )

        user = UserInfoCreate(**user_updated)
        user_info = AuthCRUD(self.db).create_account(user)
        
        if not user_info:
            return ServiceResult(AppException.AuthCreateUserInfo())
        
        email_verification_token = Token.create_email_verification_token(
            data=dict(
                uid=str(user_info.uid),
                token_usage="email-verification-token"
            ),
            expires_delta=timedelta(hours=int(os.getenv('EMAIL_VERIFICATION_TOKEN_EXPIRES_HOURS')))
        )

        code = ''.join(random.choice(string.ascii_letters + string.digits) for x in range(5))

        EmailVerificationCode.objects.create(uid=str(user_info.uid), code=code)

        background_tasks.add_task(
            Mail.email_verification, 
            recipient=user_info.email, 
            subject="Verify Your Email for ArticleExpress!",
            code=code
        )

        response=dict(
            email_verification_token=email_verification_token
        )
        
        return ServiceResult(response)
    
    def login_account(self, user: FormData) -> ServiceResult:
        user_info = AuthCRUD(self.db).get_account_info_by_email(user.email)

        if not user_info:
            return ServiceResult(AppException.AuthenticationFailed({"message": "No matching account found!"}))
        
        user_info = AuthCRUD(self.db).get_account_info_by_email(email=user.email)

        hashed_password = user_info.password
        plain_password = user.password.get_secret_value()
        
        if not Hasher.verify_password(plain_password, hashed_password):
            return ServiceResult(AppException.AuthenticationFailed({"message": "Invalid password!"}))
        
        access_token = Token.create_access_token(
            data=dict(
                uid=str(user_info.uid),
                token_usage="access-token"
            ),
            expires_delta=timedelta(hours=int(os.getenv('ACCESS_TOKEN_EXPIRES_HOURS')))
        )

        refresh_token = Token.create_refresh_token(
            data=dict(
                uid=str(user_info.uid),
                token_usage="refresh-token"
            ),
            expires_delta=timedelta(hours=int(os.getenv('REFRESH_TOKEN_EXPIRES_HOURS')))
        )

        token = Tokens(access_token=access_token, refresh_token=refresh_token)

        user_info = AuthCRUD(self.db).update_token(user_info.uid, token)

        if not user_info:
            return ServiceResult(AppException.AuthCreateUserInfo())

        response=dict(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="Bearer"
        )

        return ServiceResult(response)    
    
    def get_refresh_token(self, token: Tokens) -> ServiceResult:
        if TokenRevoked.objects.filter(token=token.access_token).allow_filtering().first():
            return ServiceResult(AppException.ExpiredToken({"message": "Your account has been logged out. Please login again!"}))
        
        try:
            Token.decode_access_token(token.access_token)
        except ExpiredSignatureError:
            try:
                refresh_token_payload = Token.decode_refresh_token(token.refresh_token)
            except ExpiredSignatureError:
                return ServiceResult(AppException.ExpiredToken({"message": "Refresh token has expired!"}))
            except JWTError:
                return ServiceResult(AppException.InvalidToken({"message": "Invalid refresh token!"}))
            
            try:
                refresh_token_info = TokenInfo(**refresh_token_payload)
            except:
                return ServiceResult(AppException.InvalidToken({"message": "Invalid refresh token!"}))

            if AuthCRUD(self.db).check_token_exists(refresh_token_info) != token.refresh_token:
                return ServiceResult(AppException.ExpiredToken({"message": "Your account has been logged out. Please login again!"}))
            
            access_token = Token.create_access_token(
                data=dict(
                    uid=str(refresh_token_info.uid),
                    token_usage="access-token"
                ),
                expires_delta=timedelta(hours=int(os.getenv('ACCESS_TOKEN_EXPIRES_HOURS')))
            )

            refresh_token = Token.create_refresh_token(
                data=dict(
                    uid=str(refresh_token_info.uid),
                    token_usage="refresh-token"
                ),
                expires_delta=timedelta(hours=int(os.getenv('REFRESH_TOKEN_EXPIRES_HOURS')))
            )

            token = Tokens(access_token=access_token, refresh_token=refresh_token)

            user_info = AuthCRUD(self.db).update_token(refresh_token_info.uid, token)
            
            if not user_info:
                return ServiceResult(AppException.AuthCreateUserInfo()), 

            response=dict(
                access_token=access_token,
                refresh_token=refresh_token,
                token_type="Bearer"
            )

            return ServiceResult(response)
        
        except JWTError:
            return ServiceResult(AppException.InvalidToken({"message": "Invalid access token!"}))
        
        response=dict(
            access_token=token.access_token,
            refresh_token=token.refresh_token,
            token_type="Bearer"
        )
        
        return ServiceResult(response)

    def validate_current_user(self, access_token: str) -> ServiceResult:
        try:
            access_token_payload = Token.decode_access_token(access_token)
        except ExpiredSignatureError:
            return ServiceResult(AppException.ExpiredToken({"message": "Access token has expired!"}))
        except JWTError:
            return ServiceResult(AppException.InvalidToken({"message": "Invalid access token!"}))
        
        if TokenRevoked.objects.filter(token=access_token).allow_filtering().first():
            return ServiceResult(AppException.ExpiredToken({"message": "Your account has been logged out. Please login again!"}))
        
        try:
            access_token_info = TokenInfo(**access_token_payload)
        except:
            return ServiceResult(AppException.InvalidToken({"message": "Invalid access token!"}))
        
        user_info = AuthCRUD(self.db).get_account_info_by_uid(uid=access_token_info.uid)
        
        if not user_info:
            return ServiceResult(AppException.AuthenticationFailed({"message": "No matching account found!"}))
        
        if not user_info.is_verified:
            return ServiceResult(AppException.InactiveAccount({"message": "Your account is not yet activated!"}))
        
        response=dict(
            uid=user_info.uid,
            username=user_info.username,
            email=user_info.email,
        )
        
        return ServiceResult(response)
    
    def logout_account(self, user: UserInfoValidated):
        user_info = AuthCRUD(self.db).get_account_info_by_uid(uid=user.uid)
        try:
            access_token_payload = Token.decode_access_token(user_info.access_token)
        except:
            token = Tokens(access_token=None, refresh_token=None)
            AuthCRUD(self.db).update_token(uid=user.uid, token=token)

        try:
            access_token_info = TokenInfo(**access_token_payload)
        except:
            return ServiceResult(AppException.InvalidToken({"message": "Invalid access token!"}))
        
        token_ttl: int = (access_token_info.exp - datetime.now().timestamp()).__int__()
        if token_ttl > 0:
            TokenRevoked.objects.ttl(token_ttl).create(token=user_info.access_token, uid=user_info.uid, created_at=datetime.now())

        token = Tokens(access_token=None, refresh_token=None)
        AuthCRUD(self.db).update_token(uid=user.uid, token=token)

        response=dict(
            message="Your account has been successfully logged out."
        )

        return ServiceResult(response)
    
    def email_verification(self, verification_info: EmailVerification):
        if TokenRevoked.objects.filter(token=verification_info.verification_code).allow_filtering().first():
            return ServiceResult(AppException.ExpiredToken({"message": "Your account has already been activated."}))
        
        try:
            email_verification_token_payload = Token.decode_email_verification_token(verification_info.email_verification_token)
        except ExpiredSignatureError:
            return ServiceResult(AppException.ExpiredToken({"message": "Email verification token has expired!"}))
        except JWTError:
            return ServiceResult(AppException.InvalidToken({"message": "Invalid email verification token!"}))

        email_verification_token_info = TokenInfo(**email_verification_token_payload)

        email_verification_info = EmailVerificationCode.objects.filter(uid=str(email_verification_token_info.uid)).allow_filtering().first()
        email_verification_code = email_verification_info.code

        if email_verification_code != verification_info.verification_code:
            return ServiceResult(AppException.InvalidInputData({"message": "The entered verification code does not match!"}))

        AuthCRUD(self.db).update_account_status(uid=email_verification_token_info.uid)
        
        token_ttl: int = (email_verification_token_info.exp - datetime.now().timestamp()).__int__()
        if token_ttl > 0:
            TokenRevoked.objects.ttl(token_ttl).create(token=verification_info.verification_code, uid=email_verification_token_info.uid, created_at=datetime.now())

        response=dict(
            message="Account has been activated."
        )

        return ServiceResult(response)
    
    def resend_email_verification(self, user: UserInfoValidated):
        code = ''.join(random.choice(string.ascii_letters + string.digits) for x in range(5))

        EmailVerificationCode.objects.create(uid=str(user.uid), code=code)

        response=dict(
            message="The verification code has been sent to your email."
        )

        return ServiceResult(response)
    
    def forgot_password(self, form_data: ForgotPassword):        
        user_info = AuthCRUD(self.db).get_account_info_by_email(form_data.email)

        if not user_info:
            return ServiceResult(AppException.AuthenticationFailed({"message": "No matching account found!"}))
        
        change_password_token = Token.create_change_password_token(
            data=dict(
                uid=str(user_info.uid),
                token_usage="change-password-token"
            ),
            expires_delta=timedelta(hours=int(os.getenv('CHANGE_PASSWORD_TOKEN_EXPIRES_HOURS')))
        )

        response = dict(
            change_password_token=change_password_token
        )

        return ServiceResult(response)
    
    def change_password(self, form_data: ChangePassword):
        if TokenRevoked.objects.filter(token=form_data.change_password_token).allow_filtering().first():
            return ServiceResult(AppException.ExpiredToken({"message": "Access token has expired!"}))
        
        try:
            change_password_token_payload = Token.decode_change_password_token(form_data.change_password_token)
        except ExpiredSignatureError:
            return ServiceResult(AppException.ExpiredToken({"message": "Refresh token has expired!"}))
        except JWTError:
                return ServiceResult(AppException.InvalidToken({"message": "Invalid refresh token!"}))
        
        try:
            change_password_token_info = TokenInfo(**change_password_token_payload)
        except:
            return ServiceResult(AppException.InvalidToken({"message": "Invalid refresh token!"}))
        

        password = Hasher.get_password_hash(form_data.password.get_secret_value())

        user_info = AuthCRUD(self.db).update_account_password(change_password_token_info.uid, password)

        if user_info:
            token_revoked_ttl: int = (change_password_token_info.exp - datetime.now().timestamp()).__int__()
            if token_revoked_ttl > 0:
                TokenRevoked.objects.ttl(token_revoked_ttl).create(token=form_data.change_password_token, uid=change_password_token_info.uid, created_at=datetime.now())
            
            response=dict(
                message="Password has been successfully updated."
            )

            return ServiceResult(response)
        
        return ServiceResult(AppException.DataUpdatedFailed({"message": "Failed to update account information!"}))
    
    def check_username_exists(self, form_data: CheckUsernameExists):
        user_info = AuthCRUD(self.db).check_username_exists(form_data.username)
        if user_info:
            response=dict(
                message="This username has already been taken!"
            )
            return ServiceResult(response)
        
        response=dict(
            message="This username is available!"
        )
        return ServiceResult(response)
    

class AuthCRUD(AppCRUD):
    def create_account(self, user: UserInfoCreate) -> UserInfo:
        user_info = Users(username=user.username, email=user.email, password=user.password.get_secret_value())
        self.db.add(user_info)
        self.db.commit()
        self.db.refresh(user_info)
        return user_info
    
    def get_account_info_by_email(self, email: str) -> UserInfo:
        return self.db.query(Users).filter(Users.email == email).first()
    
    def get_account_info_by_uid(self, uid: str) -> UserInfo:
        return self.db.query(Users).filter(Users.uid == uid).first()
    
    def get_account_info_by_username(self, username: str) -> UserInfo:
        return self.db.query(Users).filter(Users.username == username).first()
    
    def check_token_exists(self, token: TokenInfo) -> str:
        return self.db.query(Users).filter(Users.uid == token.uid).first().refresh_token
    
    def check_username_exists(self, username: str) -> bool:
        return self.db.query(Users).filter(Users.username == username).first()
    
    def update_token(self, uid: str, token: Tokens) -> UserInfo:
        user_info = self.db.query(Users).filter(Users.uid == uid).first()
        user_info.access_token = token.access_token
        user_info.refresh_token = token.refresh_token
        self.db.commit()
        self.db.refresh(user_info)
        return user_info
    
    def update_account_status(self, uid: str) -> UserInfo:
        user_info = self.db.query(Users).filter(Users.uid == uid).first()
        user_info.is_verified = True
        self.db.commit()
        self.db.refresh(user_info)
        return user_info
    
    def update_account_password(self, uid: str, password: str):
        user_info = self.db.query(Users).filter(Users.uid == uid).first()
        user_info.password = password
        self.db.commit()
        self.db.refresh(user_info)
        return user_info
    
