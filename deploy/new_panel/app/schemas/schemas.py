from typing import Optional, List
from pydantic import BaseModel
from datetime import datetime

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenPayload(BaseModel):
    sub: Optional[int] = None

class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    password: str

class UserUpdate(BaseModel):
    password: Optional[str] = None
    plan: Optional[str] = None

class UserInDBBase(UserBase):
    id: int
    is_active: bool
    is_admin: bool
    plan: str
    build_key: str
    created_at: datetime

    class Config:
        orm_mode = True

class User(UserInDBBase):
    pass

class BuildRequest(BaseModel):
    webhook_url: str

class LogCreate(BaseModel):
    log_type: str
    content: str
    pc_name: Optional[str] = None
    ip_address: Optional[str] = None
