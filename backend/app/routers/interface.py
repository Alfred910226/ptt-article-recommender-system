
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
    return templates.TemplateResponse("forgot_password/forgot_password_page.html", {"request": request})

@router.get("/login")
async def get_login_interface(request: Request):
    return templates.TemplateResponse("login/login.html", {"request": request})