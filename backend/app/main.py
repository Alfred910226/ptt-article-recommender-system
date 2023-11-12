from fastapi import FastAPI
from app.routers import users

app = FastAPI()

app.include_router(users.router)

@app.get("/")
async def main():
    return {"message": "Welcome to Article Express!"}