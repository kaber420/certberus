import asyncio
import sys
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

from certberus.pki import PKIService
from certberus.config import load_config
from certberus.db import session, audit, models
from certberus.cli import _save_cert_to_db

async def simulate_service_issuance():
    print("--- Simulating Service Certificate Issuance ---")
    
    config = load_config()
    db_url = config["database"]["url"]
    print(f"Using database: {db_url}")
    
    session.init_db(db_url)
    # Ensure tables exist (they should, but just in case)
    await session.create_all_tables()
    
    pki = PKIService(config=config)
    
    common_name = "test-iot.local"
    print(f"Issuing certificate for: {common_name}...")
    
    try:
        # We use the internal sign_certificate which now includes validation
        # But for the log to show "Service", we need to call log_event like the API does.
        # The API calls sign_certificate, then save_cert_to_db, then log_event.
        
        cert_pem, key_pem, cert_obj = pki.sign_certificate(
            common_name, 
            alt_names=["127.0.0.1"],
            profile="router",
            authority_name="default"
        )
        
        await _save_cert_to_db(cert_obj, is_ca=False, profile="router", authority_name="default")
        
        serial_hex = hex(cert_obj.serial_number)[2:]
        
        # Manually trigger the log event as if it came from the /issue endpoint
        await audit.log_event(
            method="POST",
            endpoint="/issue",
            status_code=200,
            token_type="service",
            request_payload={"common_name": common_name, "profile": "router"},
            response_summary="Certificate issued successfully (Simulated Service Request)",
            serial_number=serial_hex
        )
        
        print(f"SUCCESS: Certificate {serial_hex} issued and logged.")
        return True
    except Exception as e:
        print(f"FAILED: {e}")
        return False

if __name__ == "__main__":
    success = asyncio.run(simulate_service_issuance())
    sys.exit(0 if success else 1)
