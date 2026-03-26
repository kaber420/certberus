from fastapi import APIRouter, HTTPException, Depends, Security
from fastapi.responses import JSONResponse
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel
import os
import datetime
from typing import List, Optional, Any
from ..pki import PKIService
from ..config import load_config, save_config
from ..db import session as db_session
from ..db.models import Certificate
from sqlmodel import select

router = APIRouter(prefix="/admin", tags=["Certberus Admin API"])

API_KEY_NAME = "X-Certberus-Token"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

# Keep a global pki instance for hot-reloading reference
global_pki = None

def get_pki_service():
    global global_pki
    if global_pki is None:
        config = load_config()
        global_pki = PKIService(config=config)
    return global_pki

async def get_admin_token(api_key: str = Security(api_key_header)):
    pki = get_pki_service()
    if pki.config["security"]["auth_mode"] == "token":
        expected_token = pki.config["security"].get("admin_token") or os.getenv("CERTBERUS_ADMIN_TOKEN")
        if not expected_token:
            expected_token = pki.config["security"].get("token", "dev_adm_token_123")
             
        if api_key != expected_token:
            raise HTTPException(status_code=403, detail="Invalid or missing Certberus Admin Token")
    return api_key

@router.get("/certificates", dependencies=[Depends(get_admin_token)])
async def list_certificates(skip: int = 0, limit: int = 100, status: Optional[str] = None):
    try:
        async with db_session.AsyncSessionLocal() as session:
            query = select(Certificate)
            if status:
                if status == "revoked":
                    query = query.where(Certificate.revoked_at != None)
                elif status == "active":
                    query = query.where(Certificate.revoked_at == None)
            query = query.offset(skip).limit(limit)
            result = await session.execute(query)
            certs = result.scalars().all()
            return certs
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/certificates/{serial}", dependencies=[Depends(get_admin_token)])
async def get_certificate(serial: str):
    async with db_session.AsyncSessionLocal() as session:
        result = await session.execute(select(Certificate).where(Certificate.serial_number == serial))
        cert = result.scalars().first()
        if not cert:
            raise HTTPException(status_code=404, detail="Certificate not found")
        return cert

class RevokeRequest(BaseModel):
    reason: str = "unspecified"

@router.post("/certificates/{serial}/revoke", dependencies=[Depends(get_admin_token)])
async def revoke_certificate(serial: str, request: RevokeRequest):
    async with db_session.AsyncSessionLocal() as session:
        result = await session.execute(select(Certificate).where(Certificate.serial_number == serial))
        cert = result.scalars().first()
        if not cert:
            raise HTTPException(status_code=404, detail="Certificate not found")
        
        if cert.revoked_at:
            raise HTTPException(status_code=400, detail="Certificate already revoked")
            
        cert.revoked_at = datetime.datetime.now(datetime.timezone.utc)
        cert.revoke_reason = request.reason
        cert.status = "revoked"
        session.add(cert)
        await session.commit()
        return {"status": "success", "message": f"Certificate {serial} revoked"}

@router.get("/config", dependencies=[Depends(get_admin_token)])
async def read_config():
    pki = get_pki_service()
    return pki.config

class ConfigPatch(BaseModel):
    security: Optional[dict] = None
    endpoints: Optional[dict] = None

@router.patch("/config", dependencies=[Depends(get_admin_token)])
async def update_config(patch: ConfigPatch):
    pki = get_pki_service()
    config = pki.config
    
    if patch.security:
        config["security"].update(patch.security)
    if patch.endpoints:
        config["endpoints"].update(patch.endpoints)
        
    save_config(config)
    pki.reload_config(config)
    
    return {"status": "success", "message": "Configuration updated and reloaded", "config": pki.config}

@router.get("/stats", dependencies=[Depends(get_admin_token)])
async def get_stats():
    async with db_session.AsyncSessionLocal() as session:
        active = (await session.execute(select(Certificate).where(Certificate.revoked_at == None))).scalars().all()
        revoked = (await session.execute(select(Certificate).where(Certificate.revoked_at != None))).scalars().all()
        return {
            "total_active": len(active),
            "total_revoked": len(revoked),
            "total": len(active) + len(revoked)
        }

@router.get("/health")
async def health_check():
    return {"status": "ok"}
