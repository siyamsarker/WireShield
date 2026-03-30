import asyncio
import os
import sys
from pathlib import Path

# Ensure mandatory runtime config exists before importing app modules.
os.environ.setdefault("WS_2FA_SECRET_KEY", "test-secret")

service_root = Path(__file__).parent.parent / "console-server"
if str(service_root) not in sys.path:
    sys.path.insert(0, str(service_root))

from app.core import database
from app.routers import console


def test_activity_logs_query_returns_rows_with_dns_join(tmp_path):
    """Regression: avoid ambiguous ORDER BY that can silently empty responses."""
    test_db = tmp_path / "activity.db"
    database.AUTH_DB_PATH = str(test_db)
    database.init_db()

    conn = database.get_db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO activity_log
        (timestamp, client_id, direction, protocol, src_ip, src_port, dst_ip, dst_port, raw_line, line_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "2026-03-29 10:00:00",
            "client-a",
            "OUT",
            "TCP",
            "10.66.66.2",
            "51515",
            "142.250.185.46",
            "443",
            "[WS-Audit] sample",
            "hash-1",
        ),
    )
    cur.execute(
        "INSERT INTO dns_cache (ip_address, domain, timestamp) VALUES (?, ?, ?)",
        ("142.250.185.46", "google.com", "2026-03-29 10:00:00"),
    )
    conn.commit()
    conn.close()

    result = asyncio.run(console.get_activity_logs(page=1, limit=30, client_id="admin"))

    assert result["total"] == 1
    assert len(result["logs"]) == 1
    assert result["logs"][0]["client_id"] == "client-a"
    assert result["logs"][0]["dst_domain"] == "google.com"
