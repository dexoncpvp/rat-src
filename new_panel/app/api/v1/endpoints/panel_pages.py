from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from pathlib import Path

router = APIRouter()

# Setup templates (assuming structure new_panel/app/api/v1/endpoints/...)
# We need to go up to new_panel/templates
# endpoints -> v1 -> api -> app -> new_panel -> templates
BASE_PATH = Path(__file__).resolve().parent.parent.parent.parent.parent
TEMPLATES_DIR = BASE_PATH / "templates"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

@router.get("/chat", response_class=HTMLResponse)
async def chat_page(request: Request):
    return templates.TemplateResponse("chat.html", {"request": request})

@router.get("/soundboard", response_class=HTMLResponse)
async def soundboard_page(request: Request):
    return templates.TemplateResponse("soundboard.html", {"request": request})
