import sys
from pathlib import Path
from fastapi.testclient import TestClient

# Add local package to path so we can import app modules
# service_root = WireShield/2fa-auth
service_root = Path(__file__).parent.parent / "2fa-auth"
if str(service_root) not in sys.path:
    sys.path.insert(0, str(service_root))

from app.main import app
from app.core.security import rate_limiter
from app.core import database

def setup_function():
    """Reset rate limiter and DB before each test."""
    rate_limiter._hits.clear()
    # Reset DB path if needed, or we can mock get_db
    # For rate limit tests, DB interaction allows flow to proceed 
    # (since limits are checked before DB usually, but setup-start checks user existence first? 
    # No, dependency is checked first in route signature).
    # @router.post(..., rate_limit: None = Depends(rate_limiter))
    # So rate limit check happens BEFORE body execution.
    # So DB doesn't matter for 429 checks!
    pass

from app.core import config

def test_rate_limit_blocks_burst(tmp_path):
    # Configure DB for test
    test_db = tmp_path / "test.db"
    # We must patch the variable in the database module because it was imported directly
    database.AUTH_DB_PATH = str(test_db)
    database.init_db()

    # Configure limit for this test
    rate_limiter.max_requests = 2
    rate_limiter.window_seconds = 60
    rate_limiter._hits.clear()

    client = TestClient(app)
    payload = {"client_id": "client-1"}

    # 1st and 2nd should pass rate limit (result likely 200 or 400 or 500, but NOT 429)
    # Since DB is init, it might actually work or return 200/400.
    res1 = client.post("/api/setup-start", data=payload)
    res2 = client.post("/api/setup-start", data=payload)
    res3 = client.post("/api/setup-start", data=payload)

    assert res1.status_code != 429
    assert res2.status_code != 429
    
    # 3rd should be blocked
    assert res3.status_code == 429
    assert "Too many requests" in res3.json()["detail"]

def test_rate_limit_allows_after_window(tmp_path):
    import time
    
    # Configure DB for test
    test_db = tmp_path / "test2.db"
    database.AUTH_DB_PATH = str(test_db)
    database.init_db()
    
    # Configure limit
    rate_limiter.max_requests = 1
    rate_limiter.window_seconds = 1
    rate_limiter._hits.clear()
    
    client = TestClient(app)
    payload = {"client_id": "client-2"}

    res1 = client.post("/api/setup-start", data=payload)
    assert res1.status_code != 429

    res2 = client.post("/api/setup-start", data=payload)
    assert res2.status_code == 429

    time.sleep(1.1)
    
    res3 = client.post("/api/setup-start", data=payload)
    assert res3.status_code != 429
