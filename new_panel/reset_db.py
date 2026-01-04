import sqlite3
import secrets
import uuid

conn = sqlite3.connect('optimizer_unified.db')
cursor = conn.cursor()

# Drop the old table and recreate
cursor.execute("DROP TABLE IF EXISTS tokens")
cursor.execute("DROP TABLE IF EXISTS logs")
cursor.execute("DROP TABLE IF EXISTS users")

# Create users table matching the SQLAlchemy model
cursor.execute('''
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    account_id TEXT UNIQUE,
    username TEXT UNIQUE,
    build_key TEXT UNIQUE,
    plan TEXT DEFAULT 'free',
    is_admin INTEGER DEFAULT 0,
    is_active INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')

# Create logs table
cursor.execute('''
CREATE TABLE logs (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    log_type TEXT,
    content TEXT,
    ip_address TEXT,
    pc_name TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
''')

# Create tokens table
cursor.execute('''
CREATE TABLE tokens (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    token TEXT UNIQUE,
    is_valid INTEGER,
    token_metadata TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
''')

# Create root user
root_id = "B3xon16#12"
build_key = secrets.token_urlsafe(16)
account_id = str(uuid.uuid4()).replace('-', '')[:24]

cursor.execute('''
INSERT INTO users (account_id, username, build_key, plan, is_admin, is_active)
VALUES (?, ?, ?, 'premium', 1, 1)
''', (account_id, root_id, build_key))

conn.commit()

# Verify
cursor.execute("SELECT * FROM users")
for row in cursor.fetchall():
    print("Created user:", row)

conn.close()
print("Database reset complete!")
