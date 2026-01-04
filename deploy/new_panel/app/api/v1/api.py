from fastapi import APIRouter
from app.api.v1.endpoints import auth, builder, data, stream

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(builder.router, prefix="/build", tags=["builder"])
api_router.include_router(data.router, prefix="/data", tags=["data"])
api_router.include_router(stream.router, prefix="/stream", tags=["stream"])
