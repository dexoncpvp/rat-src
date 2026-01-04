import asyncio
from app.core.database import SessionLocal, init_db
from app.models.user import User, PlanType
from app.core.security import get_password_hash
import secrets
import uuid

def create_root_user():
    db = SessionLocal()
    try:
        # Check if root exists
        user = db.query(User).filter(User.username == "root").first()
        if not user:
            print("Creating root user...")
            build_key = secrets.token_urlsafe(16)
            account_id = str(uuid.uuid4()).replace('-', '')[:24]
            
            root_user = User(
                username="root",
                password_hash=get_password_hash("B3xon16#12"),
                build_key=build_key,
                account_id=account_id,
                plan=PlanType.PREMIUM,
                is_admin=True,
                is_active=True
            )
            db.add(root_user)
            db.commit()
            print(f"Root user created. Build Key: {build_key}")
        else:
            print("Root user already exists.")
            
    except Exception as e:
        print(f"Error creating root user: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    init_db()
    create_root_user()
