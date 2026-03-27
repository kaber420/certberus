import asyncio
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

from certberus.db import session, audit, models
from sqlmodel import select

async def verify():
    print("--- Verifying Audit Logging Implementation ---")
    
    # Use a temporary sqlite DB for testing
    db_url = "sqlite+aiosqlite:///test_audit.db"
    if os.path.exists("test_audit.db"):
        os.remove("test_audit.db")
        
    print(f"Initializing test database at {db_url}...")
    session.init_db(db_url)
    await session.create_all_tables()
    
    # 1. Log a dummy event
    print("Logging a test event...")
    await audit.log_event(
        method="POST",
        endpoint="/test/endpoint",
        status_code=201,
        token_type="service",
        request_payload={"key": "value", "ca_password": "secret_password"},
        response_summary="Test Success",
        serial_number="abcdef123456"
    )
    
    # 2. Verify it's in the DB
    print("Checking database for logged event...")
    async with session.AsyncSessionLocal() as db:
        result = await db.execute(select(models.AuditLog))
        logs = result.scalars().all()
        
        if not logs:
            print("FAILED: No logs found in database!")
            return False
            
        log = logs[0]
        print(f"Found log: {log.method} {log.endpoint} (Status: {log.status_code})")
        
        # Check masking
        if "secret_password" in log.request_payload:
            print("FAILED: Sensitive data was NOT masked!")
            return False
        else:
            print("SUCCESS: Sensitive data was correctly masked.")
            
        if log.serial_number != "abcdef123456":
            print(f"FAILED: Serial number mismatch! Expected abcdef123456, got {log.serial_number}")
            return False
            
    print("--- Verification Successful! ---")
    return True

if __name__ == "__main__":
    success = asyncio.run(verify())
    if os.path.exists("test_audit.db"):
        os.remove("test_audit.db")
    sys.exit(0 if success else 1)
