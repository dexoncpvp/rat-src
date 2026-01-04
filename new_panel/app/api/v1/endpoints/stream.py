from fastapi import APIRouter, HTTPException
from app.services.stream_manager import stream_manager

router = APIRouter()

@router.get("/stats/{player}")
async def get_stream_stats(player: str):
    stats = stream_manager.get_stats(player)
    if not stats:
        raise HTTPException(status_code=404, detail="Player not found or not connected")
    
    return {
        "success": True,
        "player": player,
        "streaming": stats.get('streaming', False),
        "quality": stats.get('quality', 85),
        "fps": stats.get('fps', 30),
        "last_frame": stats.get('last_frame')
    }
