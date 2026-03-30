from fastapi import APIRouter
from app.core.database import get_db

router = APIRouter()

@router.get("/health", tags=["system"])
async def health_check():
    """Health check endpoint to verify service and DB status."""
    status = {"status": "ok", "database": "unknown"}
    try:
        conn = get_db()
        conn.cursor().execute("SELECT 1")
        conn.close()
        status["database"] = "ok"
    except Exception as e:
        status["status"] = "error"
        status["database"] = str(e)
    return status
