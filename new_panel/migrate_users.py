
import sqlite3
import os

# Path to database on VPS
DB_PATH = "/opt/niggaware/new_panel/optimizer_unified.db"

def migrate():
    if not os.path.exists(DB_PATH):
        print(f"Database not found at {DB_PATH}")
        return

    print(f"Connecting to database at {DB_PATH}...")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Get existing columns
    cursor.execute("PRAGMA table_info(users)")
    columns = [info[1] for info in cursor.fetchall()]
    
    # Add password_hash
    if "password_hash" not in columns:
        print("Adding column: password_hash")
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN password_hash VARCHAR")
        except Exception as e:
            print(f"Error adding password_hash: {e}")
    else:
        print("Column password_hash already exists.")

    # Add leaderboard_name
    if "leaderboard_name" not in columns:
        print("Adding column: leaderboard_name")
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN leaderboard_name VARCHAR")
            # SQLite doesn't support adding UNIQUE constraint via ALTER TABLE easily without re-creation,
            # but we can add a unique index.
            cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS ix_users_leaderboard_name ON users (leaderboard_name)")
        except Exception as e:
            print(f"Error adding leaderboard_name: {e}")
    else:
        print("Column leaderboard_name already exists.")

    # Add leaderboard_changed_at
    if "leaderboard_changed_at" not in columns:
        print("Adding column: leaderboard_changed_at")
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN leaderboard_changed_at DATETIME")
        except Exception as e:
            print(f"Error adding leaderboard_changed_at: {e}")
    else:
        print("Column leaderboard_changed_at already exists.")

    conn.commit()
    conn.close()
    print("Migration complete.")

if __name__ == "__main__":
    migrate()
