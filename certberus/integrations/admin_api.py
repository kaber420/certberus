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
from ..db.models import Certificate, Authority
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

@router.get("/cas", dependencies=[Depends(get_admin_token)])
async def list_cas():
    async with db_session.AsyncSessionLocal() as session:
        result = await session.execute(select(Authority))
        cas = result.scalars().all()
        return cas

class CreateCARequest(BaseModel):
    name: str
    root_password: Optional[str] = None
    inter_password: Optional[str] = None
    permitted_domains: Optional[List[str]] = None
    permitted_ips: Optional[List[str]] = None
    valid_days: int = 3650

@router.post("/cas/intermediate", dependencies=[Depends(get_admin_token)])
async def create_intermediate_ca(request: CreateCARequest):
    pki = get_pki_service()
    try:
        cert = pki.create_intermediate_ca(
            name=request.name,
            root_password=request.root_password,
            inter_password=request.inter_password,
            permitted_domains=request.permitted_domains,
            permitted_ips=request.permitted_ips,
            valid_days=request.valid_days
        )
        
        async with db_session.AsyncSessionLocal() as session:
            existing = (await session.execute(select(Authority).where(Authority.name == request.name))).scalars().first()
            if not existing:
                auth = Authority(name=request.name)
                session.add(auth)
                await session.commit()
                
        return {"status": "success", "message": f"Intermediate CA '{request.name}' created"}
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"PKI Error: {str(e)}")

@router.get("/stats", dependencies=[Depends(get_admin_token)])
async def get_stats():
    async with db_session.AsyncSessionLocal() as session:
        certs = (await session.execute(select(Certificate))).scalars().all()
        authorities = (await session.execute(select(Authority))).scalars().all()
        auth_map = {a.id: a.name for a in authorities}
        
        stats_by_authority = {}
        total_active = 0
        total_revoked = 0
        total_certs = len(certs)
        
        for cert in certs:
            auth_name = auth_map.get(cert.authority_id, "default") if getattr(cert, "authority_id", None) else "default"
            if auth_name not in stats_by_authority:
                stats_by_authority[auth_name] = {"active": 0, "revoked": 0, "total": 0}
            
            stats_by_authority[auth_name]["total"] += 1
            if cert.revoked_at:
                total_revoked += 1
                stats_by_authority[auth_name]["revoked"] += 1
            else:
                total_active += 1
                stats_by_authority[auth_name]["active"] += 1
                
        return {
            "total_active": total_active,
            "total_revoked": total_revoked,
            "total": total_certs,
            "by_authority": stats_by_authority
        }

@router.get("/health")
async def health_check():
    return {"status": "ok"}
