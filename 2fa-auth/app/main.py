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

from pathlib import Path

# ... (inside file)

# Resolve static path relative to this file
# app/main.py -> app/ -> 2fa-auth/ -> static
static_path = Path(__file__).parent.parent / "static"
app.mount("/static", StaticFiles(directory=str(static_path), check_dir=False), name="static")

# Include Routers
app.include_router(auth.router)
app.include_router(console.router)
app.include_router(health.router)

if __name__ == "__main__":
    # If run directly for debug
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
