from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from cassandra.cqlengine.management import sync_table
from cassandra.cqlengine import connection

from app.routers import users, auth, interface
from app.models_cassandra.users import TokenRevoked, EmailInProcess, EmailVerificationCode
from app.utils.app_exceptions import AppExceptionCase
from app.utils.app_exceptions import app_exception_handler


@asynccontextmanager
async def lifespan(app: FastAPI):
    connection.setup(['cassandra'], "article_express", port=9042, protocol_version=3)
    sync_table(TokenRevoked)
    sync_table(EmailInProcess)
    sync_table(EmailVerificationCode)
    yield


app = FastAPI(lifespan = lifespan)

app.mount("/static", StaticFiles(directory="app/static"), name="static")

@app.exception_handler(AppExceptionCase)
async def custom_app_exception_handler(request, e):
    return await app_exception_handler(request, e)

app.include_router(users.router)
app.include_router(auth.router)
app.include_router(interface.router)
