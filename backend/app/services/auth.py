import os
from datetime import timedelta, datetime

from jose import JWTError, ExpiredSignatureError

from app.services.main import AppService, AppCRUD
from app.schemas.auth import UserInfo, UserInfoCreate, FormData, TokenInfo, Tokens, UserInfoValidated
from app.models_postgres.users import Users
from app.utils.service_result import ServiceResult
from app.utils.app_exceptions import AppException
from app.utils.jwt import Token
from app.utils.hashing import Hasher
from app.models_cassandra.users import TokenRevoked

class AuthService(AppService):
    def create_account(self, user: UserInfoCreate) -> ServiceResult:
        if AuthCRUD(self.db).check_if_username_exists(user):
            return ServiceResult(AppException.UserInfoConflict({"message": "Username is already taken!"}))
        
        if AuthCRUD(self.db).check_if_email_exists(user):
            return ServiceResult(AppException.UserInfoConflict({"message": "Email is already taken!"}))
        
        user_updated = dict(
            username=user.username,
            email=user.email,
            password=Hasher.get_password_hash(user.password.get_secret_value())
        )

        user = UserInfoCreate(**user_updated)
        user_info = AuthCRUD(self.db).create_account(user)
        
        if not user_info:
            return ServiceResult(AppException.AuthCreateUserInfo())
        return ServiceResult(user_info)
    
    def login_account(self, user: FormData) -> ServiceResult:
        if not AuthCRUD(self.db).check_if_email_exists(user):
            return ServiceResult(AppException.AuthenticationFailed({"message": "No matching accounts have been found!"}))
        
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

            if AuthCRUD(self.db).check_if_the_token_exists(refresh_token_info) != token.refresh_token:
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
            return ServiceResult(AppException.AuthenticationFailed({"message": "No matching accounts have been found!"}))
        
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
        
    

class AuthCRUD(AppCRUD):
    def create_account(self, user: UserInfoCreate) -> UserInfo:
        user_info = Users(username=user.username, email=user.email, password=user.password.get_secret_value())
        self.db.add(user_info)
        self.db.commit()
        self.db.refresh(user_info)
        return user_info
    
    def check_if_username_exists(self, user: UserInfoCreate) -> bool:
        result = self.db.query(Users).filter(Users.username == user.username).first()
        if result:
            return True
        return False
    
    def check_if_email_exists(self, user: UserInfoCreate) -> bool:
        result = self.db.query(Users).filter(Users.email == user.email).first()
        if result:
            return True
        return False
    
    def get_account_info_by_email(self, email: str) -> UserInfo:
        return self.db.query(Users).filter(Users.email == email).first()
    
    def get_account_info_by_uid(self, uid: str) -> UserInfo:
        return self.db.query(Users).filter(Users.uid == uid).first()
    
    def check_if_the_token_exists(self, token: TokenInfo) -> str:
        return self.db.query(Users).filter(Users.uid == token.uid).first().refresh_token
    
    def update_token(self, uid: str, token: Tokens) -> UserInfo:
        user_info = self.db.query(Users).filter(Users.uid == uid).first()
        user_info.access_token = token.access_token
        user_info.refresh_token = token.refresh_token
        self.db.commit()
        self.db.refresh(user_info)
        return user_info

    
