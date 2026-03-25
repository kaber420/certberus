from fastapi import APIRouter
from fastapi.responses import FileResponse
import os
from ..pki import PKIService

router = APIRouter(prefix="/_certberus", tags=["certberus"])
pki = PKIService()

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

def include_certberus_router(app):
    """Helper to include the certberus router in a FastAPI app."""
    app.include_router(router)
