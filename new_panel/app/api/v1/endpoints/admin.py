from typing import Any, List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import or_, desc
from app.api import deps
from app.core.database import get_db
from app.models.user import User, PlanType
from app.schemas.schemas import User as UserSchema
from pydantic import BaseModel

router = APIRouter()

class PlanUpdate(BaseModel):
    plan: str

@router.get("/users/stats")
def read_user_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(deps.get_current_active_superuser),
) -> Any:
    """Get user statistics (counts)"""
    total = db.query(User).count()
    free = db.query(User).filter(User.plan == 'free').count()
    premium = db.query(User).filter(User.plan == 'premium').count()
    return {
        "total": total,
        "free": free,
        "premium": premium
    }

@router.get("/users", response_model=List[UserSchema])
def read_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(deps.get_current_active_superuser),
    search: str = "",
    limit: int = 50,
) -> Any:
    """Search users or return recent ones"""
    query = db.query(User)
    
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            or_(
                User.username.ilike(search_term),
                User.build_key.ilike(search_term)
            )
        )
        users = query.limit(limit).all()
    else:
        # Default: Return latest 10 users to avoid loading massive list
        users = query.order_by(User.id.desc()).limit(10).all()
        
    return users

@router.post("/users/{user_id}/plan")
def update_user_plan(
    user_id: int,
    plan_update: PlanUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(deps.get_current_active_superuser),
) -> Any:
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if plan_update.plan.lower() not in [p.value for p in PlanType]:
        raise HTTPException(status_code=400, detail="Invalid plan type")
        
    user.plan = plan_update.plan.lower()
    db.commit()
    return {"success": True}

@router.post("/users/{user_id}/toggle")
def toggle_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(deps.get_current_active_superuser),
) -> Any:
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.is_admin:
        raise HTTPException(status_code=400, detail="Cannot disable admin")
        
    user.is_active = not user.is_active
    db.commit()
    return {"success": True, "is_active": user.is_active}

@router.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(deps.get_current_active_superuser),
) -> Any:
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.is_admin:
        raise HTTPException(status_code=400, detail="Cannot delete admin")
        
    db.delete(user)
    db.commit()
    return {"success": True}

class BlacklistAdd(BaseModel):
    ip: str

@router.get("/blacklist")
def list_blacklist(current_user: User = Depends(deps.get_current_active_superuser)):
    from app.services.blacklist import get_blacklist
    return {"ips": get_blacklist()}

@router.post("/blacklist")
def add_blacklist(
    data: BlacklistAdd,
    current_user: User = Depends(deps.get_current_active_superuser)
):
    from app.services.blacklist import add_ip
    add_ip(data.ip)
    return {"success": True}

@router.delete("/blacklist")
def remove_blacklist(
    ip: str,
    current_user: User = Depends(deps.get_current_active_superuser)
):
    from app.services.blacklist import remove_ip
    remove_ip(ip)
    return {"success": True}
