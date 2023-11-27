
from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates

router = APIRouter(
    tags = ['User interface']
)

templates = Jinja2Templates(directory = "app/templates")

@router.get("/")
async def index(request: Request):
    return templates.TemplateResponse("/home/index.html", {"request": request})