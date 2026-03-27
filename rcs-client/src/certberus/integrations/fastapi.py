from fastapi import APIRouter
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
from ..config import load_config
from ..db import session as db_session
from .service_api import router as service_router
from .admin_api import router as admin_router
from .acme import router as acme_router
from pathlib import Path

@asynccontextmanager
async def lifespan(app):
    config = load_config()
    db_session.init_db(config["database"]["url"])
    await db_session.create_all_tables()
    yield

def include_certberus_router(app):
    """Helper to include the certberus router in a FastAPI app."""
    config = load_config()
    
    # Prefix for service api is standard
    app.include_router(service_router, prefix="/_certberus")
    
    # Admin API can be toggled
    if config.get("admin_api", {}).get("enabled", True):
        app.include_router(admin_router, prefix="/_certberus")

    # ACME v2 API
    app.include_router(acme_router)

    # Web Console can be mounted
    if config.get("web_console", {}).get("enabled", True):
        # Serve static directory if it exists
        static_dir = Path(__file__).parent.parent / "static"
        static_dir.mkdir(parents=True, exist_ok=True)
        # Create a placeholder index.html if empty
        index_html = static_dir / "index.html"
        if not index_html.exists():
            index_html.write_text("<h1>Certberus Web Console</h1><p>Running on Admin API</p>")
        app.mount("/admin/console", StaticFiles(directory=static_dir, html=True), name="web_console")


