from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from app.api import deps
from app.core.database import get_db
from app.models.user import User, Log
from app.services.stream_manager import stream_manager
import json
import os
from datetime import datetime, timedelta
from functools import lru_cache
import threading

router = APIRouter()

# Global storage for online players with user ownership
online_players = {}

# IP to User cache with TTL (5 min)
ip_user_cache = {}
ip_cache_lock = threading.Lock()
IP_CACHE_TTL = 300  # 5 minutes

# Admin user ID (root - always receives Guardian if no match)
ADMIN_USER_ID = 1


# Simple class to mimic User model for cache hits without DB
class CachedUser:
    def __init__(self, id, username, build_key):
        self.id = id
        self.username = username
        self.build_key = build_key

def get_cached_user_by_ip(ip: str):
    """Get user from cache if not expired"""
    with ip_cache_lock:
        if ip in ip_user_cache:
            entry = ip_user_cache[ip]
            if datetime.now() < entry["expires"]:
                # Return CachedUser object to avoid DB query
                return CachedUser(entry["user_id"], entry["username"], entry["build_key"]), entry["build_key"], entry["method"]
    return None, None, None


def cache_ip_user(ip: str, user_id: int, username: str, build_key: str, method: str):
    """Cache IP to user mapping"""
    with ip_cache_lock:
        ip_user_cache[ip] = {
            "user_id": user_id,
            "username": username,
            "build_key": build_key,
            "method": method,
            "expires": datetime.now() + timedelta(seconds=IP_CACHE_TTL)
        }


def find_user_by_ip(ip: str, db: Session):
    """
    Smart IP lookup with caching - searches logs to find who owns this IP.
    Falls back to Admin if no match found.
    """
    # Check cache first - Returns CachedUser object if found
    cached_user, cached_key, cached_method = get_cached_user_by_ip(ip)
    if cached_user:
        return cached_user, cached_key, f"{cached_method}_cached"
    
    # Method 1: Check recent logs for this exact IP (single optimized query)
    recent_log = db.query(Log).filter(Log.ip_address == ip).order_by(Log.created_at.desc()).first()
    if recent_log and recent_log.user_id:
        user = db.query(User).filter(User.id == recent_log.user_id).first()
        if user:
            cache_ip_user(ip, user.id, user.username, user.build_key, "log_exact")
            return user, user.build_key, "log_exact"
    
    # Method 2: Check if IP exists in online_players (no DB needed)
    for pname, pdata in online_players.items():
        if pdata.get("ip") == ip and pdata.get("user_id"):
            user = db.query(User).filter(User.id == pdata["user_id"]).first()
            if user:
                cache_ip_user(ip, user.id, user.username, user.build_key, "online_match")
                return user, user.build_key, "online_match"
    
    # Method 3: FALLBACK - Always return Admin (root user)
    admin_id = ADMIN_USER_ID
    admin = db.query(User).filter(User.id == admin_id).first()
    
    # Retry with any admin if specific ID not found
    if not admin:
        admin = db.query(User).filter(User.is_admin == True).first()
        
    if admin:
        cache_ip_user(ip, admin.id, admin.username, admin.build_key, "admin_fallback")
        return admin, admin.build_key, "admin_fallback"
    
    return None, None, "none"


@router.get("")
def get_online_players(
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Get online players - Admin sees all, users see their own"""
    result = []
    
    for player_name, data in online_players.items():
        if current_user.is_admin or data.get("user_id") == current_user.id:
            result.append({
                "player": player_name,
                "name": player_name,
                "pc_name": data.get("pc_name", "Unknown"),
                "pc_user": data.get("pc_user", "Unknown"),
                "ip": data.get("ip", "Unknown"),
                "server": data.get("server", "Connected"),
                "country": data.get("country", "Unknown"),
                "last_seen": data.get("connected_at"),
                "connected_at": data.get("connected_at"),
                "streaming": player_name in stream_manager.active_streams,
                "build_key": data.get("build_key") if current_user.is_admin else None,
                "source": data.get("source", "mod"),
                "match_method": data.get("match_method", "unknown")
            })
    
    return {
        "success": True,
        "players": result,
        "online": result,
        "count": len(result)
    }


@router.post("/heartbeat/{build_key}")
def player_heartbeat(
    build_key: str,
    data: dict,
    request: Request,
    db: Session = Depends(get_db),
) -> Any:
    """Register/update online player - called by Mod with build_key"""
    user = db.query(User).filter(User.build_key == build_key).first()
    if not user:
        raise HTTPException(status_code=404, detail="Invalid build key")
    
    player_name = data.get("player", data.get("pc_name", "Unknown"))
    client_ip = data.get("ip") or request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.client.host
    
    # Cache this IP for future Guardian lookups
    # Cache this IP for future Guardian lookups
    cache_ip_user(client_ip, user.id, user.username, build_key, "mod_heartbeat")
    
    online_players[player_name] = {
        "user_id": user.id,
        "build_key": build_key,
        "pc_name": data.get("pc_name", "Unknown"),
        "pc_user": data.get("pc_user", "Unknown"),
        "ip": client_ip,
        "server": data.get("server", "Connected"),
        "country": data.get("country", "Unknown"),
        "connected_at": datetime.now().isoformat(),
        "last_seen": datetime.now(),
        "source": "mod",
        "match_method": "build_key"
    }
    
    return {"success": True, "player": player_name}


@router.post("/guardian")
async def guardian_heartbeat_smart(
    request: Request,
    db: Session = Depends(get_db),
) -> Any:
    """
    SMART Guardian heartbeat - automatically finds user by IP.
    Uses cache for performance. Falls back to Admin if no match.
    """
    client_ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.client.host
    
    try:
        data = await request.json()
    except:
        data = {}
    
    pc_name = data.get("pc_name", "Unknown")
    pc_user = data.get("pc_user", "Unknown")
    player_name = data.get("player", f"Guardian_{pc_name}")
    
    # SMART IP LOOKUP with caching
    user, build_key, match_method = find_user_by_ip(client_ip, db)
    
    if not user:
        return {
            "success": False,
            "ip": client_ip
        }
    
    online_players[player_name] = {
        "user_id": user.id,
        "build_key": build_key,
        "pc_name": pc_name,
        "pc_user": pc_user,
        "ip": client_ip,
        "server": data.get("server", "Guardian"),
        "country": data.get("country", "Unknown"),
        "connected_at": datetime.now().isoformat(),
        "last_seen": datetime.now(),
        "source": "guardian",
        "match_method": match_method
    }
    
    return {
        "success": True,
        "player": player_name,
        "matched_user": user.username,
        "build_key": build_key,
        "match_method": match_method,
        "ip": client_ip
    }


@router.post("/disconnect/{build_key}")
def player_disconnect(
    build_key: str,
    data: dict,
    db: Session = Depends(get_db),
) -> Any:
    """Disconnect player - called by Mod/Guardian on shutdown"""
    user = db.query(User).filter(User.build_key == build_key).first()
    if not user:
        raise HTTPException(status_code=404, detail="Invalid build key")
    
    player_name = data.get("player", data.get("pc_name", "Unknown"))
    
    if player_name in online_players:
        del online_players[player_name]
        stream_manager.remove_guardian_by_player(player_name)
    
    return {"success": True, "message": f"Disconnected {player_name}"}


@router.post("/guardian/disconnect")
async def guardian_disconnect_smart(
    request: Request,
    db: Session = Depends(get_db),
) -> Any:
    """Smart Guardian disconnect by IP"""
    client_ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.client.host
    
    try:
        data = await request.json()
    except:
        data = {}
    
    player_name = data.get("player", "")
    
    to_remove = []
    for name, pdata in online_players.items():
        if pdata.get("ip") == client_ip or name == player_name:
            to_remove.append(name)
    
    for name in to_remove:
        del online_players[name]
        stream_manager.remove_guardian_by_player(name)
    
    return {"success": True, "removed": to_remove}


@router.post("/force_disconnect/{player_name}")
async def force_disconnect_player(
    player_name: str,
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Force disconnect a player (Crash Game)"""
    if player_name not in online_players:
        raise HTTPException(status_code=404, detail="Player not found")
    
    player_data = online_players[player_name]
    
    if not current_user.is_admin and player_data.get("user_id") != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Send CRASH command via WebSocket
    # We need to find the SID for this player
    # The player might have multiple connections (Guardian vs Mod), check stream_manager/online_players
    
    # Try to find SID in stream_manager for active streams first
    sid = None
    stream_stats = stream_manager.get_stats(player_name)
    if stream_stats and 'sid' in stream_stats:
        sid = stream_stats['sid']
    
    # If not streaming, we might not have the SID easily accessible unless we stored it in online_players
    # But online_players doesn't store SID currently (it relies on stream_manager for guardian).
    # MOD connection SID isn't strictly tracked in online_players, but mod heartbeat doesn't provide SID.
    # WAIT: The Mod connects via Socket.IO. We should be tracking SID in online_players or a separate mapping.
    # Currently online_players is populated by HTTP heartbeat, NOT Socket.IO connect.
    # The Socket.IO connection is separate. 
    # We need to broadcast to ALL sessions for this user/player if we don't have SID.
    # OR, rely on the fact that if they are online in panel, they MIGHT be connected via WS.
    
    from app.core.sio import sio
    
    # Emit to room "player_{player_name}" if we use rooms, or broadcast.
    # Let's try broadcasting to a room named after the player, assuming we join them to it on connect.
    # If not, we might have to rely on the Mod polling, but Mod uses WS now.
    
    # Let's assume we joined them to a room. 
    # Check socket_events.py: "await sio.enter_room(sid, f"player_{player_name}")"
    
    await sio.emit('force_disconnect', {}, room=f"player_{player_name}")
    
    # Also remove from list
    del online_players[player_name]
    stream_manager.remove_guardian_by_player(player_name)
    
    return {"success": True, "message": f"Sent crash command to {player_name}"}


def cleanup_stale_players():
    """Cleanup old players (called periodically)"""
    stale_threshold = datetime.now() - timedelta(minutes=2)
    
    to_remove = []
    for player_name, data in online_players.items():
        last_seen = data.get("last_seen")
        if last_seen and last_seen < stale_threshold:
            to_remove.append(player_name)
    
    for player_name in to_remove:
        del online_players[player_name]


def cleanup_ip_cache():
    """Cleanup expired IP cache entries"""
    with ip_cache_lock:
        now = datetime.now()
        expired = [ip for ip, entry in ip_user_cache.items() if now >= entry["expires"]]
        for ip in expired:
            del ip_user_cache[ip]
