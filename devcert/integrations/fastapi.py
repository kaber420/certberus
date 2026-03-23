from fastapi import APIRouter
from fastapi.responses import FileResponse
import os
from ..pki import PKIService

router = APIRouter(prefix="/_devcert", tags=["devcert"])
pki = PKIService()

@router.get("/ca.pem", response_class=FileResponse)
async def get_ca():
    """Download the devcert Root CA for trust store installation."""
    if not os.path.exists(pki.ca_path):
        return {"error": "CA not initialized"}
    return FileResponse(
        path=pki.ca_path,
        filename="devcert-rootCA.pem",
        media_type="application/x-x509-ca-cert"
    )

def include_devcert_router(app):
    """Helper to include the devcert router in a FastAPI app."""
    app.include_router(router)
