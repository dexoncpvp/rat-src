from app.core.database import SessionLocal, init_db
from app.models.user import User, Log, Token
import json
import os

def check_data():
    init_db() # Create tables if missing
    db = SessionLocal()
    try:
        # 1. Check Tokens (for DonutSMP)
        tokens = db.query(Token).all()
        print(f"Total Tokens: {len(tokens)}")
        usernames = set()
        for t in tokens:
            # Try to get username from metadata or fields if they exist
            # Token model might not have username field directly if it was just added in my head? 
            # Let's check metadata
            try:
                meta = json.loads(t.token_metadata or "{}")
                if 'username' in meta: usernames.add(meta['username'])
            except: pass
        print(f"Unique Usernames in Tokens: {len(usernames)}")
        print(f"Sample Usernames: {list(usernames)[:5]}")

        # 2. Check Logs (for Browser)
        logs = db.query(Log).all()
        print(f"Total Logs: {len(logs)}")
        
        counts = {}
        for l in logs:
            counts[l.log_type] = counts.get(l.log_type, 0) + 1
            
        print("Log Types Breakdown:")
        for k, v in counts.items():
            print(f"  - {k}: {v}")
            
        # 3. Check for ZIP uploads that could be converted
        zip_logs = db.query(Log).filter(Log.log_type == 'zip_upload').all()
        print(f"\nPotential ZIPs to convert: {len(zip_logs)}")
        
        if zip_logs:
            l = zip_logs[0]
            print(f"Sample ZIP Log Content: {l.content}")
            
    finally:
        db.close()

if __name__ == "__main__":
    check_data()
