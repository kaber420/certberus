from fastapi import APIRouter, HTTPException, Depends, Security
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel
import os
from typing import List, Optional
from cryptography.hazmat.primitives import hashes
from ..pki import PKIService
from ..config import load_config

router = APIRouter(prefix="/_certberus", tags=["certberus"])
config = load_config()
pki = PKIService(config=config)

API_KEY_NAME = "X-Certberus-Token"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

async def get_api_key(api_key: str = Security(api_key_header)):
    if config["security"]["auth_mode"] == "token":
        # In a real scenario, this token should be loaded from config or environment
        expected_token = os.getenv("CERTBERUS_AUTH_TOKEN")
        if not expected_token:
             # Fallback to a development token if not set
             expected_token = "dev_token_123"
             
        if api_key != expected_token:
            raise HTTPException(status_code=403, detail="Invalid or missing Certberus Token")
    return api_key

class IssueRequest(BaseModel):
    common_name: str
    alt_names: Optional[List[str]] = None
    ca_password: Optional[str] = None

@router.get("/ca.pem", response_class=FileResponse)
async def get_ca():
    """Download the certberus Root CA for trust store installation."""
    if not os.path.exists(pki.ca_path):
        return {"error": "CA not initialized"}
    return FileResponse(
        path=pki.ca_path,
        filename="certberus-rootCA.pem",
        media_type="application/x-x509-ca-cert"
    )

@router.post("/issue", dependencies=[Depends(get_api_key)])
async def issue_cert(request: IssueRequest):
    """Programmatically issue a certificate."""
    try:
        cert_pem, key_pem, cert_obj = pki.sign_certificate(
            request.common_name, 
            request.alt_names, 
            request.ca_password
        )
        
        # Optionally save to DB if using CLI-like behavior
        # from ..cli import save_cert_to_db
        # save_cert_to_db(cert_obj)

        return {
            "certificate": cert_pem.decode(),
            "key": key_pem.decode(),
            "serial_number": hex(cert_obj.serial_number)[2:],
            "fingerprint": cert_obj.fingerprint(hashes.SHA256()).hex()
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Issuance failed: {e}")

def include_certberus_router(app):
    """Helper to include the certberus router in a FastAPI app."""
    app.include_router(router)
