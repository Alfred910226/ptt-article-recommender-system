from typing import Union
from datetime import datetime, timedelta
import os

import bcrypt
from jose import jwt

class Token():
    """
    Create Access Token
    """
    @staticmethod
    def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now() + expires_delta
        else:
            expire = datetime.now() + timedelta(hours=1)
        to_encode.update({'exp': expire})

        encodeed_jwt = jwt.encode(to_encode, os.getenv('ACCESS_TOKEN_SECRET_KEY'), algorithm=os.getenv('ACCESS_TOKEN_ALGORITHM'))
        return encodeed_jwt
    
    @staticmethod
    def decode_access_token(token):
        return jwt.decode(token, os.getenv('ACCESS_TOKEN_SECRET_KEY'), algorithms=os.getenv('ACCESS_TOKEN_ALGORITHM'))
    
    """
    Create Refresh Token
    """
    
    @staticmethod
    def create_refresh_token(data: dict, expires_delta: Union[timedelta, None] = None):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now() + expires_delta
        else:
            expire = datetime.now() + timedelta(hours=24)
        to_encode.update({'exp': expire})

        encodeed_jwt = jwt.encode(to_encode, os.getenv('REFRESH_TOKEN_SECRET_KEY'), algorithm=os.getenv('REFRESH_TOKEN_ALGORITHM'))
        return encodeed_jwt
    
    @staticmethod
    def decode_refresh_token(token):
        return jwt.decode(token, os.getenv('REFRESH_TOKEN_SECRET_KEY'), algorithms=os.getenv('REFRESH_TOKEN_ALGORITHM'))
    
    """
    Create Email Verification Token
    """
    
    @staticmethod
    def create_email_verification_token(data: dict, expires_delta: Union[timedelta, None] = None):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now() + expires_delta
        else:
            expire = datetime.now() + timedelta(hours=1)
        to_encode.update({'exp': expire})

        encodeed_jwt = jwt.encode(to_encode, os.getenv('EMAIL_VERIFICATION_TOKEN_SECRET_KEY'), algorithm=os.getenv('EMAIL_VERIFICATION_TOKEN_ALGORITHM'))
        return encodeed_jwt
    
    @staticmethod
    def decode_email_verification_token(token):
        return jwt.decode(token, os.getenv('EMAIL_VERIFICATION_TOKEN_SECRET_KEY'), algorithms=os.getenv('EMAIL_VERIFICATION_TOKEN_ALGORITHM'))
        
    """
    Create forgot password Token
    """
    
    @staticmethod
    def create_change_password_token(data: dict, expires_delta: Union[timedelta, None] = None):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now() + expires_delta
        else:
            expire = datetime.now() + timedelta(hours=1)
        to_encode.update({'exp': expire})

        encodeed_jwt = jwt.encode(to_encode, os.getenv('CHANGE_PASSWORD_TOKEN_SECRET_KEY'), algorithm=os.getenv('CHANGE_PASSWORD_TOKEN_ALGORITHM'))
        return encodeed_jwt
    
    @staticmethod
    def decode_change_password_token(token):
        return jwt.decode(token, os.getenv('CHANGE_PASSWORD_TOKEN_SECRET_KEY'), algorithms=os.getenv('CHANGE_PASSWORD_TOKEN_ALGORITHM'))