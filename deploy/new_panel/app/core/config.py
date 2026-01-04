import os
from pydantic_settings import BaseSettings
from typing import List

class Settings(BaseSettings):
    PROJECT_NAME: str = "Optimizer Panel Unified"
    API_V1_STR: str = "/api"
    SECRET_KEY: str = os.getenv("SECRET_KEY", "OpT1m1z3r_S3cr3t_K3y_2025_UNIFIED!")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days
    
    # Database
    DATABASE_URL: str = "sqlite:///./optimizer_unified.db"
    
    # Security
    ADMIN_USERNAME: str = "root"
    ADMIN_PASSWORD: str = "B3xon16#12"
    
    # Builder
    AES_KEY: bytes = b'd3x0n_0pt1m1z3r_k3y_2025_s3cr3!!'
    PROJECT_DIR: str = os.getenv("PROJECT_DIR", "/home/dex/Desktop/newrat")
    
    # CORS
    BACKEND_CORS_ORIGINS: List[str] = ["*"]

    class Config:
        case_sensitive = True

settings = Settings()
