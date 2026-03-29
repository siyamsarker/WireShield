import asyncio
import os
import sys
from pathlib import Path

os.environ.setdefault("WS_2FA_SECRET_KEY", "test-secret")

service_root = Path(__file__).parent.parent / "2fa-auth"
if str(service_root) not in sys.path:
    sys.path.insert(0, str(service_root))

from app.core import database
from app.routers import console


def test_bandwidth_usage_supports_user_and_date_filters(tmp_path):
    test_db = tmp_path / "bandwidth.db"
    database.AUTH_DB_PATH = str(test_db)
    database.init_db()

    conn = database.get_db()
    cur = conn.cursor()
    cur.executemany(
        """
        INSERT INTO bandwidth_usage (client_id, scan_date, rx_bytes, tx_bytes)
        VALUES (?, ?, ?, ?)
        """,
        [
            ("alice", "2026-03-01", 1024, 2048),
            ("alice", "2026-03-02", 4096, 1024),
            ("bob", "2026-03-02", 8192, 2048),
        ],
    )
    conn.commit()
    conn.close()

    result = asyncio.run(
        console.get_bandwidth_usage(
            days=30,
            user="alice",
            start_date="2026-03-01",
            end_date="2026-03-02",
            client_id="admin",
        )
    )

    assert result["labels"] == ["2026-03-01", "2026-03-02"]
    assert len(result["upload"]) == 2
    assert len(result["download"]) == 2
    assert result["upload"][0] > 0
    assert result["download"][1] > 0
