import logging
import warnings
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.responses import Response

from app.core.config import LOG_LEVEL
from app.core.database import init_db
from app.core.tasks import start_background_tasks
from app.core.sniffer import DNSSniffer
from app.routers import auth, health, console, agents

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Suppress passlib warning if underlying lib is updated
warnings.filterwarnings("ignore", category=UserWarning, module="passlib")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle events: startup and shutdown."""
    init_db()

    # Reconcile enrolled agents against the running wg0 peer table before
    # background tasks start. Heals drift from a failed wg_syncconf during
    # enrollment or a wg0 restart that happened while the console was down.
    try:
        from app.core.agents import reconcile_wg_peers
        synced = reconcile_wg_peers()
        if synced:
            logger.info(f"Startup reconcile: applied {synced} missing/stale wg0 peer(s)")
    except Exception as exc:
        logger.error(f"Startup WireGuard reconciliation failed: {exc}")

    start_background_tasks()
    
    # Start DNS Sniffer for domain logging
    sniffer = DNSSniffer()
    sniffer.start()
    
    yield
    
    sniffer.stop()

app = FastAPI(
    title="WireShield 2FA",
    version="3.2.0",
    lifespan=lifespan,
    docs_url=None, # Disable Swagger UI in production
    redoc_url=None
)

# Configure Jinja2 templates
templates_path = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(templates_path))

from pathlib import Path

# ... (inside file)

# Resolve static path relative to this file
# app/main.py -> app/ -> console-server/ -> static
static_path = Path(__file__).parent.parent / "static"

class CachedStaticFiles(StaticFiles):
    """StaticFiles with a Cache-Control header so repeat page loads (e.g. a
    captive-portal denial page hit by repeated OS connectivity probes) skip
    the conditional-GET round trip instead of re-validating every request.
    # ponytail: filenames aren't content-hashed, so max-age is capped at a
    # day rather than marked immutable; add hashed filenames if longer wanted.
    """
    def file_response(self, *args, **kwargs) -> Response:
        response = super().file_response(*args, **kwargs)
        response.headers.setdefault("Cache-Control", "public, max-age=86400")
        return response

app.mount("/static", CachedStaticFiles(directory=str(static_path), check_dir=False), name="static")

# Make templates available to routers
app.state.templates = templates

@app.middleware("http")
async def no_cache_console(request, call_next):
    """The admin console (page + /api/console/* data) must never be cached —
    a stale dashboard/bandwidth/user read is a correctness and security bug,
    unlike the static assets above which are safe to cache."""
    response = await call_next(request)
    path = request.url.path
    if path == "/console" or path.startswith("/api/console"):
        response.headers["Cache-Control"] = "no-store"
    return response

# Include Routers
app.include_router(auth.router)
app.include_router(console.router)
app.include_router(health.router)
app.include_router(agents.router)

if __name__ == "__main__":
    # If run directly for debug
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
