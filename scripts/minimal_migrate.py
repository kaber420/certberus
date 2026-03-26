import sqlite3
import os

db_path = "/home/kaber420/.local/share/certberus/certs.db"
print(f"Migrating database at: {db_path}")

if not os.path.exists(db_path):
    print("Database file does not exist. Nothing to migrate.")
else:
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # 1. Create authority table
        print("Creating 'authority' table...")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS authority (
                id TEXT NOT NULL, 
                name TEXT NOT NULL, 
                active BOOLEAN NOT NULL, 
                created_at DATETIME NOT NULL, 
                PRIMARY KEY (id)
            )
        """)
        
        # 2. Add authority_id column to certificate table
        print("Adding 'authority_id' column to 'certificate' table...")
        try:
            cursor.execute("ALTER TABLE certificate ADD COLUMN authority_id TEXT")
            print("Column 'authority_id' added successfully.")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e).lower():
                print("Column 'authority_id' already exists.")
            else:
                print(f"OperationalError: {e}")

        conn.commit()
        print("✅ Migration successful!")
    except Exception as e:
        print(f"❌ Migration failed: {e}")
    finally:
        if 'conn' in locals():
            conn.close()
