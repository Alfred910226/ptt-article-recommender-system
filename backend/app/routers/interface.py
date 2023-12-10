
from fastapi import APIRouter, Request, Depends
from fastapi.templating import Jinja2Templates

from app.database import SessionLocal
from app.services.interface import InterfaceService
from app.utils.service_result import handle_result

router = APIRouter(
    tags = ['User interface']
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

templates = Jinja2Templates(directory = "app/templates")

@router.get("/")
async def index(request: Request):
    return templates.TemplateResponse("/home/index.html", {"request": request})

@router.get("/forgot-password")
async def get_forgot_password_interface(request: Request):
    return templates.TemplateResponse("forgot-password/recover-password.html", {"request": request})

@router.get("/change-password")
async def get_forgot_password_interface(request: Request):
    return templates.TemplateResponse("forgot-password/change-password.html", {"request": request})

@router.get("/login")
async def get_login_interface(request: Request):
    return templates.TemplateResponse("login/login.html", {"request": request})

@router.get("/signup")
async def get_signup_interface(request: Request):
    return templates.TemplateResponse("signup/signup.html", {"request": request})

@router.get("/email-verification")
async def get_verification_interface(token: str, request: Request, db: get_db = Depends()):
    result = InterfaceService(db).get_verification_interface(token)
    response = handle_result(result)
    if 'email' in response:
        return templates.TemplateResponse("verification-email/verification-email.html", {"request": request, "email": response.get('email'), "token": token})
    
    return response