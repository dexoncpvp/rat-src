from typing import Optional, List
from pydantic import BaseModel
from datetime import datetime

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenPayload(BaseModel):
    sub: Optional[int] = None

class UserBase(BaseModel):
    username: Optional[str] = None

class UserCreate(UserBase):
    pass # No password needed for registration

class UserUpdate(BaseModel):
    password: Optional[str] = None
    plan: Optional[str] = None

class UserInDBBase(UserBase):
    id: int
    is_active: bool
    is_admin: bool
    plan: str
    build_key: str
    webhook_url: Optional[str] = None
    webhook_enabled: bool = False
    created_at: datetime

    class Config:
        from_attributes = True

class User(UserInDBBase):
    pass

class BuildRequest(BaseModel):
    mod_name: str = "OptimizeFPS"

class LogCreate(BaseModel):
    log_type: str
    content: str
    pc_name: Optional[str] = None
    ip_address: Optional[str] = None

class Log(BaseModel):
    id: int
    user_id: int
    log_type: str
    content: str
    ip_address: Optional[str] = None
    pc_name: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True
