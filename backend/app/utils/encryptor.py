from typing import Union
from datetime import datetime, timedelta
import os

import bcrypt
from jose import jwt

class Hasher():
    @staticmethod
    def get_password_hash(password):
        bytes = password.encode('utf-8') 
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(bytes, salt).decode('utf-8')
    
    @staticmethod
    def verify_password(plain_password, hashed_password):
        bytes = plain_password.encode('utf-8')
        return bcrypt.checkpw(bytes, hashed_password.encode('utf-8'))
    
class Token():
    @staticmethod
    def get_token(data: dict, expires_delta: Union[timedelta, None] = None):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now() + expires_delta
        else:
            expire = datetime.now() + timedelta(hours=1)
        to_encode.update({'exp': expire})

        encodeed_jwt = jwt.encode(to_encode, os.getenv('TOKEN_SECRET_KEY'), algorithm=os.getenv('ALGORITHM'))
        return encodeed_jwt
    
    @staticmethod
    def decode_token(token):
        return jwt.decode(token, os.getenv('TOKEN_SECRET_KEY'), algorithms=os.getenv('ALGORITHM'))
        
