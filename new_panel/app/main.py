from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import socketio
from app.core.config import settings
from app.api.v1.api import api_router
from app.core.database import init_db
from app.api.socket_events import register_socket_events

# Create FastAPI app
app = FastAPI(title=settings.PROJECT_NAME)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Socket.IO
from app.core.sio import sio
sio_app = socketio.ASGIApp(sio, app)

# Register Socket Events
register_socket_events(sio)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Include API router
app.include_router(api_router, prefix=settings.API_V1_STR)

from app.api.v1.endpoints import panel_pages
app.include_router(panel_pages.router)

@app.on_event("startup")
async def startup_event():
    print("Starting up...")
    init_db()

from fastapi import Request
from fastapi.templating import Jinja2Templates
templates = Jinja2Templates(directory="templates")

@app.middleware("http")
async def ip_blacklist_middleware(request: Request, call_next):
    # Skip for static files to ensure basic styles load if needed (optional)
    # But usually block everything.
    
    client_ip = request.client.host
    # Allow localhost to prevent accidental lockout
    if client_ip not in ["127.0.0.1", "localhost", "::1"]:
        try:
            from app.services.blacklist import is_blacklisted
            if is_blacklisted(client_ip):
                return templates.TemplateResponse("blocked.html", {"request": request}, status_code=403)
        except Exception as e:
            print(f"Middleware Error: {e}")
            pass

    response = await call_next(request)
    return response

@app.get("/")
async def root():
    return {"message": "Optimizer Panel Unified API"}

# Support legacy/Guardian V5 upload path (POST /upload/)
from app.api.v1.endpoints.data import upload_guardian_zip
from app.core.database import get_db
from sqlalchemy.orm import Session
from fastapi import Depends

@app.post("/upload/")
async def legacy_upload(request: Request, db: Session = Depends(get_db)):
    """Redirect/Handle standard Guardian uploads hitting the root /upload/ endpoint"""
    # Simply delegate to the new handler
    return await upload_guardian_zip(request, db)
