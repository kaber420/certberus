import asyncio
import sqlite3
import os
from pathlib import Path
from certberus.config import load_config

async def migrate():
    config = load_config()
    db_url = config.get("database", {}).get("url", "")
    if not db_url.startswith("sqlite+aiosqlite:///"):
        print(f"Unsupported DB URL for manual migration: {db_url}")
        return

    db_path = db_url.replace("sqlite+aiosqlite:///", "")
    print(f"Migrating database at: {db_path}")

    if not os.path.exists(db_path):
        print("Database file does not exist. Nothing to migrate (it will be created normally).")
        return

    # Use standard sqlite3 for structural changes
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        # 1. Create authority table if it doesn't exist
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
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e).lower():
                print("Column 'authority_id' already exists.")
            else:
                print(f"Note: {e}")

        conn.commit()
        print("✅ Migration successful!")
    except Exception as e:
        print(f"❌ Migration failed: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    asyncio.run(migrate())
