from fastapi import APIRouter, Depends, HTTPException
import aiohttp
import json
from app.api.deps import get_current_user

router = APIRouter()

API_KEY = "dcb634b3a1474bf1ba091e1cfe7aaf0d"
BASE_URL = "https://api.donutsmp.net"

@router.get("/stats/{username}")
async def get_player_stats(username: str, current_user = Depends(get_current_user)):
    """Get player stats (balance, kills, etc) from DonutSMP API"""
    url = f"{BASE_URL}/v1/stats/{username}"
    headers = {
        "Authorization": f"Bearer {API_KEY}"
    }
    
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, headers=headers) as resp:
                # Get response as text first (API may return text/plain)
                text = await resp.text()
                
                if resp.status == 200:
                    try:
                        data = json.loads(text)
                        return {"success": True, "data": data}
                    except json.JSONDecodeError:
                        return {"success": False, "error": f"Invalid JSON: {text[:200]}"}
                elif resp.status == 401:
                    return {"success": False, "error": "API Key unauthorized"}
                elif resp.status == 500:
                    try:
                        err_data = json.loads(text)
                        err_msg = err_data.get('message', 'Player not found')
                    except:
                        err_msg = text[:200] if text else "Player not found"
                    return {"success": False, "error": err_msg}
                else:
                    return {"success": False, "error": f"API Error {resp.status}: {text[:200]}"}
        except Exception as e:
            return {"success": False, "error": str(e)}



# ==================================================================================
# INTERNAL CHECK FUNCTION (No Auth Dependency)
# ==================================================================================
async def check_player_stats_internal(username: str):
    """Internal function to check stats without API dependency"""
    url = f"{BASE_URL}/v1/stats/{username}"
    headers = {
        "Authorization": f"Bearer {API_KEY}"
    }
    
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, headers=headers) as resp:
                text = await resp.text()
                if resp.status == 200:
                    try:
                        return {"success": True, "data": json.loads(text)}
                    except:
                        return None
        except:
            return None
    return None

# ==================================================================================
# SETTINGS ENDPOINT
# ==================================================================================
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.user import User

class DonutSMPSettings(BaseModel):
    webhook: str
    min_balance: int

@router.post("/settings")
async def update_settings(
    settings: DonutSMPSettings,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update DonutSMP settings for the user"""
    # Re-attach user to session
    user = db.query(User).filter(User.id == current_user.id).first()
    if user:
        user.donutsmp_webhook = settings.webhook
        user.donutsmp_min_balance = settings.min_balance
        db.commit()
        return {"status": "success"}
    
    raise HTTPException(status_code=404, detail="User not found")

@router.get("/settings")
async def get_settings(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get current DonutSMP settings"""
    user = db.query(User).filter(User.id == current_user.id).first()
    if user:
        return {
            "webhook": user.donutsmp_webhook or "",
            "min_balance": user.donutsmp_min_balance or 0
        }
    return {"webhook": "", "min_balance": 0}
