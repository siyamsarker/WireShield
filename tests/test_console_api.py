"""Tests for the console API endpoints (called directly, bypassing auth dependency)."""
import asyncio
import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("WS_2FA_SECRET_KEY", "wireshield-test-secret-key")
os.environ.setdefault("WS_CSRF_DISABLE", "1")
service_root = Path(__file__).parent.parent / "console-server"
if str(service_root) not in sys.path:
    sys.path.insert(0, str(service_root))

from app.core import database
from app.routers import console


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _insert_audit(conn, client_id="alice", action="2FA_VERIFY", status="success",
                  ip="10.66.66.2", timestamp=None):
    if timestamp:
        conn.execute(
            "INSERT INTO audit_log (client_id, action, status, ip_address, timestamp) "
            "VALUES (?, ?, ?, ?, ?)",
            (client_id, action, status, ip, timestamp),
        )
    else:
        conn.execute(
            "INSERT INTO audit_log (client_id, action, status, ip_address) VALUES (?, ?, ?, ?)",
            (client_id, action, status, ip),
        )


def _insert_activity(conn, direction="OUT", client_id="alice",
                     dst_ip="1.2.3.4", src_ip="10.66.66.2",
                     timestamp="2026-03-29 10:00:00",
                     hash_suffix="a"):
    conn.execute(
        "INSERT INTO activity_log "
        "(timestamp, client_id, direction, protocol, src_ip, src_port, "
        "dst_ip, dst_port, raw_line, line_hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (timestamp, client_id, direction, "TCP", src_ip, "12345",
         dst_ip, "443", "[WS-Audit] sample", f"hash-{hash_suffix}"),
    )


# ---------------------------------------------------------------------------
# Audit logs
# ---------------------------------------------------------------------------

def test_audit_logs_returns_all_rows(tmp_db):
    conn = database.get_db()
    _insert_audit(conn, status="success")
    _insert_audit(conn, client_id="bob", status="denied")
    conn.commit()
    conn.close()

    result = asyncio.run(console.get_audit_logs(page=1, limit=30, client_id="admin"))
    assert result["total"] == 2


def test_audit_logs_status_filter_success(tmp_db):
    conn = database.get_db()
    _insert_audit(conn, status="success")
    _insert_audit(conn, status="denied")
    _insert_audit(conn, status="granted")
    conn.commit()
    conn.close()

    result = asyncio.run(
        console.get_audit_logs(page=1, limit=30, status_filter="success", client_id="admin")
    )
    assert result["total"] == 1
    assert result["logs"][0]["status"] == "success"


def test_audit_logs_status_filter_denied(tmp_db):
    conn = database.get_db()
    _insert_audit(conn, status="denied")
    _insert_audit(conn, status="granted")
    conn.commit()
    conn.close()

    result = asyncio.run(
        console.get_audit_logs(page=1, limit=30, status_filter="denied", client_id="admin")
    )
    assert result["total"] == 1


def test_audit_logs_status_filter_case_insensitive(tmp_db):
    """LOWER(status) = LOWER(?) so 'SUCCESS' matches filter 'success'."""
    conn = database.get_db()
    conn.execute(
        "INSERT INTO audit_log (client_id, action, status, ip_address) VALUES (?, ?, ?, ?)",
        ("alice", "2FA_VERIFY", "SUCCESS", "10.0.0.1"),
    )
    conn.commit()
    conn.close()

    result = asyncio.run(
        console.get_audit_logs(page=1, limit=30, status_filter="success", client_id="admin")
    )
    assert result["total"] == 1


def test_audit_logs_no_status_filter_returns_all(tmp_db):
    conn = database.get_db()
    for s in ("success", "denied", "granted", "invalid_code"):
        _insert_audit(conn, status=s)
    conn.commit()
    conn.close()

    result = asyncio.run(
        console.get_audit_logs(page=1, limit=30, client_id="admin")
    )
    assert result["total"] == 4


def test_audit_logs_date_range_filter(tmp_db):
    conn = database.get_db()
    _insert_audit(conn, timestamp="2026-03-01 10:00:00")
    _insert_audit(conn, timestamp="2026-03-15 10:00:00")
    _insert_audit(conn, timestamp="2026-04-01 10:00:00")
    conn.commit()
    conn.close()

    result = asyncio.run(
        console.get_audit_logs(
            page=1, limit=30,
            start_date="2026-03-01", end_date="2026-03-31",
            client_id="admin",
        )
    )
    assert result["total"] == 2


def test_audit_logs_client_filter(tmp_db):
    conn = database.get_db()
    _insert_audit(conn, client_id="alice")
    _insert_audit(conn, client_id="bob")
    conn.commit()
    conn.close()

    result = asyncio.run(
        console.get_audit_logs(page=1, limit=30, client_filter="alice", client_id="admin")
    )
    assert result["total"] == 1
    assert result["logs"][0]["client_id"] == "alice"


def test_audit_logs_pagination(tmp_db):
    conn = database.get_db()
    for i in range(15):
        _insert_audit(conn)
    conn.commit()
    conn.close()

    page1 = asyncio.run(console.get_audit_logs(page=1, limit=10, client_id="admin"))
    page2 = asyncio.run(console.get_audit_logs(page=2, limit=10, client_id="admin"))

    assert page1["total"] == 15
    assert len(page1["logs"]) == 10
    assert len(page2["logs"]) == 5
    assert page1["pages"] == 2


def test_audit_logs_empty_db_returns_zero(tmp_db):
    result = asyncio.run(console.get_audit_logs(page=1, limit=30, client_id="admin"))
    assert result["total"] == 0
    assert result["logs"] == []


# ---------------------------------------------------------------------------
# Activity logs
# ---------------------------------------------------------------------------

def test_activity_logs_direction_filter_out(tmp_db):
    conn = database.get_db()
    _insert_activity(conn, direction="OUT", hash_suffix="out")
    _insert_activity(conn, direction="IN", hash_suffix="in")
    conn.commit()
    conn.close()

    result = asyncio.run(
        console.get_activity_logs(page=1, limit=30, direction_filter="OUT", client_id="admin")
    )
    assert result["total"] == 1
    assert result["logs"][0]["direction"] == "OUT"


def test_activity_logs_direction_filter_in(tmp_db):
    conn = database.get_db()
    _insert_activity(conn, direction="OUT", hash_suffix="out2")
    _insert_activity(conn, direction="IN", hash_suffix="in2")
    conn.commit()
    conn.close()

    result = asyncio.run(
        console.get_activity_logs(page=1, limit=30, direction_filter="IN", client_id="admin")
    )
    assert result["total"] == 1
    assert result["logs"][0]["direction"] == "IN"


def test_activity_logs_direction_filter_case_insensitive(tmp_db):
    """UPPER(a.direction) = UPPER(?) so 'in' matches stored 'IN'."""
    conn = database.get_db()
    _insert_activity(conn, direction="IN", hash_suffix="ci")
    conn.commit()
    conn.close()

    result = asyncio.run(
        console.get_activity_logs(page=1, limit=30, direction_filter="in", client_id="admin")
    )
    assert result["total"] == 1


def test_activity_logs_no_direction_filter_returns_all(tmp_db):
    conn = database.get_db()
    _insert_activity(conn, direction="OUT", hash_suffix="nd1")
    _insert_activity(conn, direction="IN", hash_suffix="nd2")
    conn.commit()
    conn.close()

    result = asyncio.run(
        console.get_activity_logs(page=1, limit=30, client_id="admin")
    )
    assert result["total"] == 2


def test_activity_logs_dns_join_resolves_domain(tmp_db):
    conn = database.get_db()
    _insert_activity(conn, dst_ip="142.250.185.46", hash_suffix="dns")
    conn.execute(
        "INSERT INTO dns_cache (ip_address, domain) VALUES (?, ?)",
        ("142.250.185.46", "google.com"),
    )
    conn.commit()
    conn.close()

    result = asyncio.run(console.get_activity_logs(page=1, limit=30, client_id="admin"))
    assert result["logs"][0]["dst_domain"] == "google.com"


def test_activity_logs_no_dns_entry_returns_none_domain(tmp_db):
    conn = database.get_db()
    _insert_activity(conn, dst_ip="1.2.3.4", hash_suffix="nodns")
    conn.commit()
    conn.close()

    result = asyncio.run(console.get_activity_logs(page=1, limit=30, client_id="admin"))
    assert result["logs"][0]["dst_domain"] is None


def test_activity_logs_client_filter(tmp_db):
    conn = database.get_db()
    _insert_activity(conn, client_id="alice", hash_suffix="cf1")
    _insert_activity(conn, client_id="bob", hash_suffix="cf2")
    conn.commit()
    conn.close()

    result = asyncio.run(
        console.get_activity_logs(page=1, limit=30, client_filter="alice", client_id="admin")
    )
    assert result["total"] == 1
    assert result["logs"][0]["client_id"] == "alice"


def test_activity_logs_empty_db_returns_zero(tmp_db):
    result = asyncio.run(console.get_activity_logs(page=1, limit=30, client_id="admin"))
    assert result["total"] == 0
    assert result["logs"] == []


# ---------------------------------------------------------------------------
# Bandwidth usage
# ---------------------------------------------------------------------------

def test_bandwidth_usage_user_filter(tmp_db):
    conn = database.get_db()
    conn.execute(
        "INSERT INTO bandwidth_usage (client_id, scan_date, rx_bytes, tx_bytes) "
        "VALUES (?, ?, ?, ?)",
        ("alice", "2026-03-01", 1024, 2048),
    )
    conn.execute(
        "INSERT INTO bandwidth_usage (client_id, scan_date, rx_bytes, tx_bytes) "
        "VALUES (?, ?, ?, ?)",
        ("bob", "2026-03-01", 8192, 4096),
    )
    conn.commit()
    conn.close()

    result = asyncio.run(
        console.get_bandwidth_usage(
            days=30, user="alice",
            start_date="2026-03-01", end_date="2026-03-01",
            client_id="admin",
        )
    )
    # tx_bytes → upload, rx_bytes → download
    assert sum(result["upload"]) == 2048
    assert sum(result["download"]) == 1024


def test_bandwidth_usage_gap_fills_zero_for_missing_dates(tmp_db):
    conn = database.get_db()
    conn.execute(
        "INSERT INTO bandwidth_usage (client_id, scan_date, rx_bytes, tx_bytes) "
        "VALUES (?, ?, ?, ?)",
        ("alice", "2026-03-01", 500, 1000),
    )
    conn.commit()
    conn.close()

    result = asyncio.run(
        console.get_bandwidth_usage(
            days=3, start_date="2026-03-01", end_date="2026-03-03", client_id="admin"
        )
    )
    assert "2026-03-01" in result["labels"]
    assert "2026-03-02" in result["labels"]
    assert "2026-03-03" in result["labels"]
    assert len(result["upload"]) == len(result["labels"])
    assert len(result["download"]) == len(result["labels"])
    # Days 02 and 03 have no data → zero
    idx = result["labels"].index("2026-03-02")
    assert result["upload"][idx] == 0
    assert result["download"][idx] == 0


def test_bandwidth_usage_multiple_users_aggregated(tmp_db):
    """When no user filter, all users' data is summed per date."""
    conn = database.get_db()
    conn.execute(
        "INSERT INTO bandwidth_usage (client_id, scan_date, rx_bytes, tx_bytes) "
        "VALUES (?, ?, ?, ?)",
        ("alice", "2026-03-01", 100, 200),
    )
    conn.execute(
        "INSERT INTO bandwidth_usage (client_id, scan_date, rx_bytes, tx_bytes) "
        "VALUES (?, ?, ?, ?)",
        ("bob", "2026-03-01", 300, 400),
    )
    conn.commit()
    conn.close()

    result = asyncio.run(
        console.get_bandwidth_usage(
            days=1, start_date="2026-03-01", end_date="2026-03-01", client_id="admin"
        )
    )
    assert sum(result["upload"]) == 600  # 200 + 400
    assert sum(result["download"]) == 400  # 100 + 300


def test_bandwidth_usage_empty_db_returns_all_zeros(tmp_db):
    result = asyncio.run(
        console.get_bandwidth_usage(
            days=1, start_date="2026-03-01", end_date="2026-03-01", client_id="admin"
        )
    )
    assert result["labels"] == ["2026-03-01"]
    assert result["upload"] == [0]
    assert result["download"] == [0]


# ---------------------------------------------------------------------------
# Users endpoint
# ---------------------------------------------------------------------------

def test_get_users_returns_all(tmp_db):
    conn = database.get_db()
    conn.execute("INSERT INTO users (client_id, enabled) VALUES (?, ?)", ("user1", 1))
    conn.execute("INSERT INTO users (client_id, enabled) VALUES (?, ?)", ("user2", 0))
    conn.commit()
    conn.close()

    result = asyncio.run(console.get_users(page=1, limit=20, client_id="admin"))
    assert result["total"] == 2
    ids = [u["client_id"] for u in result["users"]]
    assert "user1" in ids and "user2" in ids


def test_get_users_search_filter(tmp_db):
    conn = database.get_db()
    conn.execute("INSERT INTO users (client_id, enabled) VALUES (?, ?)", ("alice_vpn", 1))
    conn.execute("INSERT INTO users (client_id, enabled) VALUES (?, ?)", ("bob_vpn", 1))
    conn.commit()
    conn.close()

    result = asyncio.run(console.get_users(page=1, limit=20, search="alice", client_id="admin"))
    assert result["total"] == 1
    assert result["users"][0]["client_id"] == "alice_vpn"


def test_get_users_pagination(tmp_db):
    conn = database.get_db()
    for i in range(25):
        conn.execute(
            "INSERT INTO users (client_id, enabled) VALUES (?, ?)", (f"user{i:02d}", 1)
        )
    conn.commit()
    conn.close()

    page1 = asyncio.run(console.get_users(page=1, limit=10, client_id="admin"))
    assert page1["total"] == 25
    assert len(page1["users"]) == 10
    assert page1["pages"] == 3


def test_get_users_active_session_status(tmp_db):
    """Users with live sessions must show session_status='Active'."""
    from datetime import datetime, timedelta, timezone
    conn = database.get_db()
    conn.execute(
        "INSERT INTO users (client_id, enabled, wg_ipv4) VALUES (?, ?, ?)",
        ("active_user", 1, "10.66.66.2"),
    )
    expires = (datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "INSERT INTO sessions (client_id, session_token, expires_at, device_ip) "
        "VALUES (?, ?, ?, ?)",
        ("active_user", "hash-abc", expires, "10.66.66.2"),
    )
    conn.commit()
    conn.close()

    result = asyncio.run(console.get_users(page=1, limit=20, client_id="admin"))
    user = next(u for u in result["users"] if u["client_id"] == "active_user")
    assert user["session_status"] == "Active"


# ---------------------------------------------------------------------------
# Activity metrics
# ---------------------------------------------------------------------------

def test_activity_metrics_empty_db(tmp_db):
    result = asyncio.run(console.get_activity_metrics(client_id="admin"))
    assert result["total_logs"] == 0
    assert result["oldest_log"] is None
    assert result["newest_log"] is None


def test_activity_metrics_counts_logs(tmp_db):
    conn = database.get_db()
    _insert_activity(conn, hash_suffix="m1")
    _insert_activity(conn, hash_suffix="m2")
    conn.commit()
    conn.close()

    result = asyncio.run(console.get_activity_metrics(client_id="admin"))
    assert result["total_logs"] == 2
