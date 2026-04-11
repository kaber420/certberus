from fastapi import APIRouter, HTTPException, Depends, Security
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel
import os
import base64
from typing import List, Optional
from cryptography.hazmat.primitives import hashes
from ..pki import PKIService
from ..config import load_config
from ..cli import save_cert_to_db
from ..db.audit import log_event

router = APIRouter(tags=["Certberus Service API"])

API_KEY_NAME = "X-Certberus-Token"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

def get_pki_service():
    # En un entorno real asíncrono, PKIService podría ser inyectado, 
    # pero aquí lo instanciamos con la config actual.
    config = load_config()
    return PKIService(config=config)

async def get_service_token(api_key: str = Security(api_key_header)):
    pki = get_pki_service()
    if pki.config["security"]["auth_mode"] == "token":
        expected_token = pki.config["security"].get("service_token") or os.getenv("CERTBERUS_SERVICE_TOKEN")
        if not expected_token:
             # Fallback para dev
             expected_token = pki.config["security"].get("token", "dev_svc_token_123")
             
        if api_key != expected_token:
            raise HTTPException(status_code=403, detail="Invalid or missing Certberus Service Token")
    return api_key

class IssueRequest(BaseModel):
    common_name: str
    alt_names: Optional[List[str]] = None
    ca_password: Optional[str] = None
    authority: Optional[str] = None
    profile: str = "router"
    format: str = "pem"
    p12_password: str = ""

@router.get("/ca.pem", response_class=FileResponse)
async def get_ca():
    """Download the certberus Root CA for trust store installation."""
    pki = get_pki_service()
    if not os.path.exists(pki.ca_path):
        return JSONResponse(status_code=404, content={"error": "CA not initialized"})
    return FileResponse(
        path=pki.ca_path,
        filename="certberus-rootCA.pem",
        media_type="application/x-x509-ca-cert"
    )

@router.get("/crl.pem", response_class=FileResponse)
async def get_crl():
    """Download the current Certificate Revocation List."""
    pki = get_pki_service()
    crl_path = pki.storage_path / "crl.pem"
    if not os.path.exists(crl_path):
        return JSONResponse(status_code=404, content={"error": "CRL not found"})
    return FileResponse(
        path=crl_path,
        filename="crl.pem",
        media_type="application/pkix-crl"
    )

@router.post("/issue", dependencies=[Depends(get_service_token)])
async def issue_cert(request: IssueRequest):
    """Programmatically issue a certificate."""
    pki = get_pki_service()
    try:
        cert_pem, key_pem, cert_obj = pki.sign_certificate(
            request.common_name, 
            request.alt_names, 
            request.ca_password,
            profile=request.profile,
            authority_name=request.authority
        )
        
        save_cert_to_db(cert_obj, is_ca=False, profile=request.profile, authority_name=request.authority)

        if request.format.lower() == "p12":
            p12_bytes = pki.export_p12(cert_pem, key_pem, request.common_name, request.p12_password)
            return {
                "certificate_p12_base64": base64.b64encode(p12_bytes).decode('utf-8'),
                "serial_number": hex(cert_obj.serial_number)[2:],
                "fingerprint": cert_obj.fingerprint(hashes.SHA256()).hex()
            }

        await log_event(
            method="POST",
            endpoint="/issue",
            status_code=200,
            token_type="service",
            request_payload=request.model_dump(),
            response_summary="Certificate issued successfully",
            serial_number=hex(cert_obj.serial_number)[2:]
        )

        return {
            "certificate": cert_pem.decode(),
            "key": key_pem.decode(),
            "serial_number": hex(cert_obj.serial_number)[2:],
            "fingerprint": cert_obj.fingerprint(hashes.SHA256()).hex()
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        await log_event(
            method="POST",
            endpoint="/issue",
            status_code=500,
            token_type="service",
            request_payload=request.model_dump(),
            response_summary=f"Error: {str(e)}"
        )
        raise HTTPException(status_code=500, detail=f"Issuance failed: {e}")

class SignRequest(BaseModel):
    csr_pem: str
    ca_password: Optional[str] = None
    authority: Optional[str] = None
    profile: str = "router"
    
@router.post("/sign", dependencies=[Depends(get_service_token)])
async def sign_csr(request: SignRequest):
    """Sign an existing Certificate Signing Request (e.g. from MikroTik)."""
    pki = get_pki_service()
    
    if not pki.config.get("endpoints", {}).get("sign_csr", False):
         raise HTTPException(status_code=403, detail="CSR Signing endpoint is disabled in config")
         
    try:
        cert_pem, cert_obj = pki.sign_csr(
            request.csr_pem, 
            ca_password=request.ca_password,
            profile=request.profile,
            authority_name=request.authority
        )
        
        save_cert_to_db(cert_obj, is_ca=False, profile=request.profile, authority_name=request.authority)

        await log_event(
            method="POST",
            endpoint="/sign",
            status_code=200,
            token_type="service",
            request_payload={"csr_pem": request.csr_pem, "profile": request.profile, "authority": request.authority},
            response_summary="CSR signed successfully",
            serial_number=hex(cert_obj.serial_number)[2:]
        )

        return {
            "certificate": cert_pem.decode(),
            "serial_number": hex(cert_obj.serial_number)[2:],
            "fingerprint": cert_obj.fingerprint(hashes.SHA256()).hex()
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        await log_event(
            method="POST",
            endpoint="/sign",
            status_code=500,
            token_type="service",
            request_payload={"csr_pem": request.csr_pem},
            response_summary=f"Error: {str(e)}"
        )
        raise HTTPException(status_code=500, detail=f"Signing failed: {e}")
