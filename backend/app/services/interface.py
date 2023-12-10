from datetime import datetime

from jose import JWTError, ExpiredSignatureError

from app.services.main import AppService, AppCRUD
from app.utils.service_result import ServiceResult
from app.schemas.interface import UserInfo, TokenInfo
from app.models_postgres.users import Users
from app.models_cassandra.users import TokenRevoked
from app.utils.app_exceptions import AppException
from app.utils.jwt import Token


class InterfaceService(AppService):
    def get_verification_interface(self, token: str) -> ServiceResult:
        if TokenRevoked.objects.filter(token=token).allow_filtering().first():
            return ServiceResult(AppException.ExpiredToken({"message": "Your account has already been activated."}))
        
        try:
            email_verification_token_payload = Token.decode_email_verification_token(token)
        except ExpiredSignatureError:
            return ServiceResult(AppException.ExpiredToken({"message": "Email verification token has expired!"}))
        except JWTError:
            return ServiceResult(AppException.InvalidToken({"message": "Invalid email verification token!"}))

        email_verification_token_info = TokenInfo(**email_verification_token_payload)

        user_info = InterfaceCRUD(self.db).get_account_info_by_uid(email_verification_token_info.uid)

        token_ttl: int = (email_verification_token_info.exp - datetime.now().timestamp()).__int__()
        if token_ttl > 0:
            TokenRevoked.objects.ttl(token_ttl).create(token=token, uid=user_info.uid, created_at=datetime.now())

        response=dict(
            email=user_info.email
        )

        return ServiceResult(response)

class InterfaceCRUD(AppCRUD):
    def get_account_info_by_uid(self, uid: str) -> UserInfo:
        return self.db.query(Users).filter(Users.uid == uid).first()