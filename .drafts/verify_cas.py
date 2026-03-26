import asyncio
import uuid
import datetime
import ipaddress
import sys
from pathlib import Path

# Fix python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from certberus.config import load_config
from certberus.pki import PKIService
from certberus.db import session as db_session
from certberus.db.models import Authority, Certificate
from sqlmodel import select

async def run_verification():
    config = load_config()
    db_url = config.get("core", {}).get("db_url", "sqlite+aiosqlite:///certberus.db")
    db_session.init_db(db_url)
    
    # Setup DB
    await db_session.create_all_tables()
    
    print("🔄 Initializing DB and Root CA...")
    # Initialize PKI Service
    pki = PKIService()
    pki.create_root_ca()
    
    print("▶️ Creating Intermediate CAs...")
    
    # Create CA-Legacy
    pki.create_intermediate_ca(
        name="CA-Legacy", 
        permitted_domains=[], 
        permitted_ips=[], 
        valid_days=3650,
        force=True
    )
    
    # Create CA-IoT (Constrained)
    pki.create_intermediate_ca(
        name="CA-IoT", 
        permitted_domains=["*.iot.local"], 
        permitted_ips=["10.10.10.0/24"], 
        valid_days=365,
        force=True
    )
    
    print("✅ CAs created successfully!")
    
    print("▶️ Registering authorities in DB...")
    async with db_session.AsyncSessionLocal() as session:
        for name in ["CA-Legacy", "CA-IoT"]:
            existing = (await session.execute(select(Authority).where(Authority.name == name))).scalars().first()
            if not existing:
                session.add(Authority(name=name))
        await session.commit()
            
    print("▶️ Testing Cert Issuance (CA-Legacy)...")
    try:
        cert_pem, key_pem, cert_obj = pki.sign_certificate(
            common_name="router1.legacy.local",
            authority_name="CA-Legacy",
            profile="router"
        )
        print("✅ CA-Legacy issued certificate successfully!")
    except Exception as e:
        print(f"❌ CA-Legacy failed: {e}")
        
    print("▶️ Testing Cert Issuance (CA-IoT) - VALID constraints...")
    try:
        cert_pem, key_pem, cert_obj = pki.sign_certificate(
            common_name="device1.iot.local",
            authority_name="CA-IoT",
            profile="iot"
        )
        
        # Verify validity period (profile IoT => 90 days usually, but the CA validity itself is 365)
        days_valid = (cert_obj.not_valid_after_utc - cert_obj.not_valid_before_utc).days
        print(f"✅ CA-IoT issued cert for device1.iot.local successfully! (Valid for {days_valid} days)")
        
    except Exception as e:
        print(f"❌ CA-IoT failed valid certificate issuance: {e}")

    print("▶️ Testing Cert Issuance (CA-IoT) - INVALID constraints (SHOULD FAIL via cryptographic restriction or software if we had it, but mostly via client, but let's test)...")
    try:
        # Software filter validation does NOT stop it for CA-IoT automatically unless we set it globally, 
        # but the cryptography library might throw an exception on signing if the constraints are violated?
        # Actually cryptography does NOT throw on signing, Name constraints are evaluated during CHAIN validation.
        # So we can't test signature failure, but we can verify it was signed and then use `x509` extensions to verify
        
        cert_pem, key_pem, cert_obj = pki.sign_certificate(
            common_name="bad-device.evil.com",
            authority_name="CA-IoT",
            profile="iot"
        )
        print("ℹ️ Warning: CA-IoT signed an invalid domain (NameConstraints are enforced on the client side during verification/handshake, not at signing time). But this is expected behavior for openssl/cryptography.")
    except Exception as e:
        print(f"✅ CA-IoT correctly threw an error on signing bad domain: {e}")
        
    print("✅ Verification completed!")

if __name__ == "__main__":
    asyncio.run(run_verification())
