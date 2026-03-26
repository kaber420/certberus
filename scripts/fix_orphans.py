import asyncio
import sqlite3
import os
import uuid
from datetime import datetime

db_path = "/home/kaber420/.local/share/certberus/certs.db"

def fix_orphans():
    if not os.path.exists(db_path):
        print("Database not found.")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        # 1. Check existing authorities
        cursor.execute("SELECT id, name FROM authority")
        auths = cursor.fetchall()
        print(f"Current authorities: {auths}")

        # 2. Check certificates with NULL authority_id
        cursor.execute("SELECT id, common_name, authority_id FROM certificate")
        certs = cursor.fetchall()
        print(f"Total certificates: {len(certs)}")
        orphans = [c for c in certs if c[2] is None]
        print(f"Orphan certificates (NULL authority_id): {len(orphans)}")

        if orphans:
            # 3. Create 'default' authority if not exists
            default_auth = [a for a in auths if a[1] == 'default']
            if not default_auth:
                print("Creating 'default' authority...")
                auth_id = str(uuid.uuid4())
                now = datetime.utcnow().isoformat()
                cursor.execute("INSERT INTO authority (id, name, active, created_at) VALUES (?, ?, ?, ?)", 
                               (auth_id, 'default', 1, now))
                default_auth_id = auth_id
            else:
                default_auth_id = default_auth[0][0]

            # 4. Associate orphans
            print(f"Associating {len(orphans)} certificates with 'default' authority ({default_auth_id})...")
            cursor.execute("UPDATE certificate SET authority_id = ? WHERE authority_id IS NULL", (default_auth_id,))
            
            conn.commit()
            print("✅ Migration complete!")
        else:
            print("No orphan certificates found.")

    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    fix_orphans()
