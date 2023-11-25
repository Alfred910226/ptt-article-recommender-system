import os

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

SQLALCHEMY_DATABASE_URL = "postgresql://{username}:{password}@{hostname}:{port}/{db_name}".format(
    username=os.getenv('POSTGRES_USERNAME'), 
    password=os.getenv('POSTGRES_PASSWORD'), 
    hostname=os.getenv('POSTGRES_HOSTNAME'), 
    port=os.getenv('POSTGRES_PORT'), 
    db_name=os.getenv('POSTGRES_DB_NAME')
)

engine = create_engine(
    SQLALCHEMY_DATABASE_URL
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
