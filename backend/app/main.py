from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from cassandra.cqlengine.management import sync_table
from cassandra.cqlengine import connection

from app.routers import users, interface
from app.models_cassandra.users import TokenRevoked, EmailInProcess

@asynccontextmanager
async def lifespan(app: FastAPI):
    connection.setup(['cassandra'], "article_express", port=9042, protocol_version=3)
    sync_table(TokenRevoked)
    sync_table(EmailInProcess)
    yield


app = FastAPI(lifespan = lifespan)

app.mount("/static", StaticFiles(directory="app/static"), name="static")

app.include_router(users.router)
app.include_router(interface.router)