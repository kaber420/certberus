import asyncio
from pathlib import Path
import sys
import os

# Set PYTHONPATH
sys.path.append(os.getcwd())

from certberus.pki import PKIService
from certberus.config import load_config
from certberus.db import session as db_session
from certberus.db.models import Authority
from sqlmodel import select

async def debug_ca():
    config = load_config()
    pki = PKIService(config=config)
    
    test_name = f"debug-ca-{os.getpid()}"
    print(f"--- Starting Diagnostic for CA: {test_name} ---")
    
    # 1. Test PKI Logic
    try:
        print("Testing pki.create_intermediate_ca...")
        cert = pki.create_intermediate_ca(
            name=test_name,
            valid_days=365
        )
        if cert:
            print("✅ PKI Logic: OK (Cert generated)")
        else:
            print("⚠️ PKI Logic: OK (Cert already existed?)")
    except Exception as e:
        print(f"❌ PKI Logic: FAILED")
        import traceback
        traceback.print_exc()
        return

    # 2. Test DB Logic
    try:
        print("Testing DB session and insert...")
        db_session.init_db(config["database"]["url"])
        await db_session.create_all_tables()
        
        async with db_session.AsyncSessionLocal() as session:
            auth = Authority(name=test_name)
            session.add(auth)
            await session.commit()
            print("✅ DB Logic: OK (Record inserted)")
            
            # Cleanup
            await session.delete(auth)
            await session.commit()
            print("✅ DB Logic: OK (Record cleaned up)")
    except Exception as e:
        print(f"❌ DB Logic: FAILED")
        import traceback
        traceback.print_exc()
        return

    print("--- Diagnostic Finished Successfully ---")

if __name__ == "__main__":
    asyncio.run(debug_ca())
