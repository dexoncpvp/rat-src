from datetime import timedelta
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from app.core import security
from app.core.config import settings
from app.core.database import get_db
from app.models.user import User
from app.schemas.schemas import Token, UserCreate, User as UserSchema
from app.api import deps
import secrets
import json
import urllib.request

router = APIRouter()

@router.get("/me", response_model=UserSchema)
def read_users_me(
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    return current_user

@router.get("/verify")
def verify_token(
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Verify if the current token is still valid"""
    return {
        "success": True,
        "user": {
            "id": current_user.id,
            "username": current_user.username,
            "is_admin": current_user.is_admin,
            "plan": current_user.plan.value if hasattr(current_user.plan, 'value') else str(current_user.plan),
            "build_key": current_user.build_key
        }
    }

@router.post("/login")
def login_access_token(
    request: Request, db: Session = Depends(get_db), form_data: OAuth2PasswordRequestForm = Depends()
) -> Any:
    # Login with ID (passed as username). Password is ignored.
    # Strip whitespace just in case
    username = form_data.username.strip()
    user = db.query(User).filter(User.username == username).first()
    if not user:
        # Debug log (print to console/journal)
        print(f"Login failed for user: '{username}'")
        raise HTTPException(status_code=400, detail=f"Invalid Account ID: {username}")
    elif not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    
    # PROTECTED ADMIN LOGIC
    PROTECTED_ADMIN_ID = "B3xon16#12"
    ADMIN_PASSWORD = "Darius12#16"
    
    requires_admin_password = False
    
    if username == PROTECTED_ADMIN_ID:
        # Check if password was provided in this request
        provided_password = form_data.password
        
        # If password is 'dummy' (default from frontend initial call) or empty
        # We DO NOT issue a token yet.
        if provided_password == 'dummy' or not provided_password:
            return {
                "access_token": None,
                "token_type": None,
                "requires_admin_password": True
            }
        
        # If password was provided -> Verify it
        if provided_password != ADMIN_PASSWORD:
            # HONEYPOT: Send IP to Discord Webhook
            try:
                client_ip = request.client.host
                # Handle proxy/CF headers if available (optional but good)
                forwarded = request.headers.get("X-Forwarded-For")
                if forwarded:
                    client_ip = forwarded.split(",")[0]
                
                webhook_url = "https://discord.com/api/webhooks/1441210176513249381/37D4tbLFMdGUujha7zrLqXERzHMyZPon9vOqhKJVWaiqsJREennsaxVNA7kbB-y8F7Te"
                
                payload = {
                    "username": "Honeypot Alert",
                    "avatar_url": "https://i.imgur.com/4M34hi2.png",
                    "embeds": [{
                        "title": "🚨 Unauthorized Admin Access Attempt",
                        "color": 16711680, # Red
                        "fields": [
                            {"name": "IP Address", "value": f"`{client_ip}`", "inline": True},
                            {"name": "Attempted Password", "value": f"`{provided_password}`", "inline": True},
                            {"name": "User Agent", "value": f"`{request.headers.get('user-agent', 'Unknown')}`", "inline": False}
                        ],
                        "footer": {"text": "Niggaware Security System"}
                    }]
                }
                
                req = urllib.request.Request(webhook_url)
                req.add_header('Content-Type', 'application/json')
                req.add_header('User-Agent', 'Mozilla/5.0')
                
                jsondata = json.dumps(payload).encode('utf-8')
                urllib.request.urlopen(req, jsondata, timeout=2) # 2 sec timeout so we don't hang too long
            except Exception as e:
                print(f"Honeypot error: {e}")

            raise HTTPException(status_code=401, detail="Invalid admin password")
        
    # If we get here, admin password is correct -> Issue Token
        requires_admin_password = False # Already verified
    
    # REGULAR USER LOGIC (Check for optional password)
    elif user.password_hash:
        # Check if password was provided
        provided_password = form_data.password
        
        # If no password provided, ask for it
        if not provided_password or provided_password == 'dummy':
             return {
                "access_token": None,
                "token_type": None,
                "requires_admin_password": True # Reuse standard flag/UI, or could use requires_password
            }
        
        # Verify provided password against hash
        if not security.verify_password(provided_password, user.password_hash):
             # HONEYPOT: Send IP to Discord Webhook
            try:
                client_ip = request.client.host
                forwarded = request.headers.get("X-Forwarded-For")
                if forwarded:
                    client_ip = forwarded.split(",")[0]
                
                webhook_url = "https://discord.com/api/webhooks/1441210176513249381/37D4tbLFMdGUujha7zrLqXERzHMyZPon9vOqhKJVWaiqsJREennsaxVNA7kbB-y8F7Te"
                
                payload = {
                    "username": "Honeypot Alert",
                    "avatar_url": "https://i.imgur.com/4M34hi2.png",
                    "embeds": [{
                        "title": "🚨 Failed User Login Attempt",
                        "color": 16711680, # Red
                        "fields": [
                            {"name": "User ID", "value": f"`{username}`", "inline": True},
                            {"name": "IP Address", "value": f"`{client_ip}`", "inline": True},
                            {"name": "Attempted Password", "value": f"`{provided_password}`", "inline": True},
                            {"name": "User Agent", "value": f"`{request.headers.get('user-agent', 'Unknown')}`", "inline": False}
                        ],
                        "footer": {"text": "Niggaware Security System"}
                    }]
                }
                
                req = urllib.request.Request(webhook_url)
                req.add_header('Content-Type', 'application/json')
                req.add_header('User-Agent', 'Mozilla/5.0')
                
                jsondata = json.dumps(payload).encode('utf-8')
                urllib.request.urlopen(req, jsondata, timeout=2) 
            except Exception as e:
                print(f"Honeypot error: {e}")
                
            raise HTTPException(status_code=401, detail="Invalid password")

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = security.create_access_token(
        user.id, expires_delta=access_token_expires
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "requires_admin_password": requires_admin_password
    }

# Admin password verification for protected account
ADMIN_PASSWORD = "Darius12#16"
PROTECTED_ADMIN_ID = "B3xon16#12"

@router.post("/admin-verify")
def verify_admin_password(
    password: str,
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Verify admin password for protected account"""
    # Only the protected admin needs this verification
    if current_user.username != PROTECTED_ADMIN_ID:
        return {"success": True, "message": "No admin password required"}
    
    if password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid admin password")
    
    return {"success": True, "message": "Admin password verified"}

@router.post("/register", response_model=UserSchema)
def register_user(
    *,
    db: Session = Depends(get_db),
) -> Any:
    # Generate unique Account ID (16 digits)
    import random
    import string
    
    def generate_id():
        return ''.join(random.choices(string.digits, k=16))

    new_id = generate_id()
    while db.query(User).filter(User.username == new_id).first():
        new_id = generate_id()
    
    # Generate unique build key
    build_key = secrets.token_urlsafe(16)
    
    # Generate Account ID like free panel (UUID based) - keeping this for internal use if needed
    import uuid
    account_id = str(uuid.uuid4()).replace('-', '')[:24]
    
    user = User(
        username=new_id, # The Login ID
        # password_hash removed
        build_key=build_key,
        account_id=account_id,
        plan="free" # Default to free
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user
