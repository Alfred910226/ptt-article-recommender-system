import bcrypt

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