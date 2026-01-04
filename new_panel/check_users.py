from app.core.database import SessionLocal
from app.models.user import User

db = SessionLocal()
users = db.query(User).all()
print("Users in DB:")
for user in users:
    print(f"ID: '{user.account_id}', Plan: {user.plan}")
db.close()
