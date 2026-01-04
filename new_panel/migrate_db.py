
import sqlite3
import os

DB_FILE = "/home/dex/Desktop/newrat/new_panel/optimizer_unified.db"

def migrate():
    if not os.path.exists(DB_FILE):
        print("Database not found, skipping migration (will be created by app)")
        return

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    try:
        # Check if column exists
        cursor.execute("SELECT donutsmp_webhook FROM users LIMIT 1")
    except sqlite3.OperationalError:
        print("Adding donutsmp_webhook column...")
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN donutsmp_webhook TEXT")
            conn.commit()
        except Exception as e:
            print(f"Error adding donutsmp_webhook: {e}")

    try:
        # Check if column exists
        cursor.execute("SELECT donutsmp_min_balance FROM users LIMIT 1")
    except sqlite3.OperationalError:
        print("Adding donutsmp_min_balance column...")
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN donutsmp_min_balance INTEGER DEFAULT 1000000")
            conn.commit()
        except Exception as e:
            print(f"Error adding donutsmp_min_balance: {e}")

    conn.close()
    print("Migration check complete.")

if __name__ == "__main__":
    migrate()
