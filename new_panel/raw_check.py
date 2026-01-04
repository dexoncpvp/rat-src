import sqlite3

conn = sqlite3.connect('optimizer_unified.db')
cursor = conn.cursor()

# Get table info
cursor.execute("PRAGMA table_info(users)")
cols = cursor.fetchall()
print("Columns:", [c[1] for c in cols])

cursor.execute("SELECT * FROM users")
rows = cursor.fetchall()
print("Users found:", len(rows))
for row in rows:
    print(row)
conn.close()
