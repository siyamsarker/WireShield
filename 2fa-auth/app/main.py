import logging
import warnings
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.core.config import LOG_LEVEL
from app.core.database import init_db
from app.core.tasks import start_background_tasks
from app.routers import auth, health, console

# Setup logging
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
    start_background_tasks()
    yield
    # Cleanup if needed

app = FastAPI(
    title="WireShield 2FA",
    version="2.0.0",
    lifespan=lifespan,
    docs_url=None, # Disable Swagger UI in production
    redoc_url=None
)

# mount static files
# We assume static/ exists at the root of 2fa-auth (same directory as where app.py IS)
# Since we are moving app code to app/, we need to be careful about relative paths.
# If running main.py directly, paths might differ. 
# But we will run from 2fa-auth/ root via `python3 app.py` shim.
app.mount("/static", StaticFiles(directory="static"), name="static")

# Include Routers
app.include_router(auth.router)
app.include_router(console.router)
app.include_router(health.router)

if __name__ == "__main__":
    # If run directly for debug
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
