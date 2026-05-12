import os
import sys
from pathlib import Path

# Must be set before any app module import triggers config.py
os.environ.setdefault("WS_2FA_SECRET_KEY", "wireshield-test-secret-key")
os.environ.setdefault("WS_CSRF_DISABLE", "1")

service_root = Path(__file__).parent.parent / "console-server"
if str(service_root) not in sys.path:
    sys.path.insert(0, str(service_root))

import pytest
from app.core import database
from app.core.security import rate_limiter


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    rate_limiter._hits.clear()
    rate_limiter._call_count = 0
    yield
    rate_limiter._hits.clear()


@pytest.fixture
def tmp_db(tmp_path):
    """Fresh isolated SQLite database pointed at tmp_path."""
    db_path = tmp_path / "test.db"
    old_path = database.AUTH_DB_PATH
    database.AUTH_DB_PATH = str(db_path)
    database.init_db()
    yield db_path
    database.AUTH_DB_PATH = old_path
