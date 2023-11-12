from fastapi import FastAPI
from cassandra.cqlengine.management import sync_table
from cassandra.cqlengine import connection

from app.routers import users
from app.models.users import User, TokenRevoked

app = FastAPI()

app.include_router(users.router)

@app.on_event("startup")
async def create_table():
    connection.setup(['cassandra'], "article_express", port=9042, protocol_version=3)
    sync_table(User)
    sync_table(TokenRevoked)

@app.get("/")
async def main():
    return {"message": "Welcome to Article Express!"}