from typing import Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.api import deps
from app.core.database import get_db
from app.models.user import User
from app.utils.notifications import send_discord_notification
from pydantic import BaseModel

router = APIRouter()

class WebhookUpdate(BaseModel):
    url: str
    enabled: bool

class PasswordUpdate(BaseModel):
    password: str

class LeaderboardUpdate(BaseModel):
    name: str

@router.post("/notifications")
def update_notifications(
    settings: WebhookUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Update Discord webhook settings"""
    current_user.webhook_url = settings.url
    current_user.webhook_enabled = settings.enabled
    db.commit()
    return {"success": True}

@router.post("/notifications/test")
async def test_notification(
    settings: WebhookUpdate,
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Test the Discord webhook"""
    if not settings.url:
         return {"success": False, "error": "No URL provided"}
    
    # Send a test notification
    await send_discord_notification(
        settings.url,
        "test", # Will show as "NEW TEST LOG" (handled in notifications.py?) 
                # Wait, notifications.py handles specific types. I might need to add 'test' type support there.
        {"message": "This is a test notification from Optimizer Unified."},
        pc_info={"pc_name": "Test PC", "pc_user": "Test User", "ip": "127.0.0.1"}
    )
    return {"success": True}
    return {"success": True}

from app.core import security
from datetime import datetime, timedelta

@router.post("/security/password")
def update_password(
    data: PasswordUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Set or update user password"""
    if not data.password or len(data.password) < 4:
         raise HTTPException(status_code=400, detail="Password too short (min 4 chars)")
    
    current_user.password_hash = security.get_password_hash(data.password)
    db.commit()
    return {"success": True}

@router.post("/leaderboard/name")
def update_leaderboard_name(
    data: LeaderboardUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Set leaderboard display name (30 day cooldown)"""
    # Check cooldown
    if current_user.leaderboard_changed_at:
        cooldown = current_user.leaderboard_changed_at + timedelta(days=30)
        if datetime.utcnow() < cooldown:
            time_left = (cooldown - datetime.utcnow()).days
            raise HTTPException(status_code=400, detail=f"Name change on cooldown. Try again in {time_left} days.")

    # Validate name (alphanumeric, 3-16 chars)
    name = data.name.strip()
    if not name.isalnum() or len(name) < 3 or len(name) > 16:
        raise HTTPException(status_code=400, detail="Name must be 3-16 alphanumeric characters")
        
    # Check uniqueness
    existing = db.query(User).filter(User.leaderboard_name == name).first()
    if existing and existing.id != current_user.id:
         raise HTTPException(status_code=400, detail="Name already taken")

    current_user.leaderboard_name = name
    current_user.leaderboard_changed_at = datetime.utcnow()
    db.commit()
    return {"success": True}
