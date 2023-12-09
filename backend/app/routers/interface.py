
from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates

router = APIRouter(
    tags = ['User interface']
)

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

@router.get("/verification-email")
async def get_verification_interface(request: Request):
    return templates.TemplateResponse("verification-email/verification-email.html", {"request": request})