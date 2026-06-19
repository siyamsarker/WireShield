"""Tests for dashboard-stats and activity-metrics console API endpoints.

Functions are called directly (bypassing _check_console_access) using the
same pattern established in test_console_api.py.
"""
import asyncio
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

os.environ.setdefault("WS_2FA_SECRET_KEY", "wireshield-test-secret-key")
os.environ.setdefault("WS_CSRF_DISABLE", "1")
service_root = Path(__file__).parent.parent / "console-server"
if str(service_root) not in sys.path:
    sys.path.insert(0, str(service_root))

from app.core import database
from app.routers import console


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _fmt(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# GET /api/console/dashboard-stats
# ---------------------------------------------------------------------------

def test_dashboard_stats_empty_db(tmp_db):
    result = asyncio.run(console.get_dashboard_stats(client_id="admin"))
    assert result["total_users"] == 0
    assert result["active_sessions"] == 0
    assert result["failed_attempts_24h"] == 0
    assert result["bandwidth_24h"] == 0
    assert result["new_users_24h"] == 0
    assert "agents" in result
    assert result["agents"]["total"] == 0


def test_dashboard_stats_counts_total_users(tmp_db):
    conn = database.get_db()
    conn.execute("INSERT INTO users (client_id, enabled) VALUES ('alice', 1)")
    conn.execute("INSERT INTO users (client_id, enabled) VALUES ('bob', 1)")
    conn.execute("INSERT INTO users (client_id, enabled) VALUES ('charlie', 0)")
    conn.commit()
    conn.close()

    result = asyncio.run(console.get_dashboard_stats(client_id="admin"))
    assert result["total_users"] == 3


def test_dashboard_stats_active_session_counts_only_non_expired(tmp_db):
    conn = database.get_db()
    conn.execute("INSERT INTO users (client_id, enabled) VALUES ('alice', 1)")
    conn.execute("INSERT INTO users (client_id, enabled) VALUES ('bob', 1)")
    # alice: live session
    conn.execute(
        "INSERT INTO sessions (client_id, session_token, expires_at, device_ip) VALUES (?, ?, ?, ?)",
        ("alice", "tok1", _fmt(_now() + timedelta(hours=2)), "10.1.1.1"),
    )
    # bob: expired session — must NOT be counted
    conn.execute(
        "INSERT INTO sessions (client_id, session_token, expires_at, device_ip) VALUES (?, ?, ?, ?)",
        ("bob", "tok2", _fmt(_now() - timedelta(hours=1)), "10.1.1.2"),
    )
    conn.commit()
    conn.close()

    result = asyncio.run(console.get_dashboard_stats(client_id="admin"))
    assert result["active_sessions"] == 1


def test_dashboard_stats_failed_attempts_within_24h(tmp_db):
    conn = database.get_db()
    recent = _fmt(_now() - timedelta(hours=1))
    old    = _fmt(_now() - timedelta(hours=30))

    # recent failures: must count
    for status in ("invalid_code", "replay_detected", "ip_mismatch"):
        conn.execute(
            "INSERT INTO audit_log (client_id, action, status, ip_address, timestamp) "
            "VALUES (?, ?, ?, ?, ?)",
            ("alice", "2FA_VERIFY", status, "10.1.1.1", recent),
        )
    # old failure: outside 24h window, must NOT count
    conn.execute(
        "INSERT INTO audit_log (client_id, action, status, ip_address, timestamp) "
        "VALUES (?, ?, ?, ?, ?)",
        ("alice", "2FA_VERIFY", "denied", "10.1.1.1", old),
    )
    conn.commit()
    conn.close()

    result = asyncio.run(console.get_dashboard_stats(client_id="admin"))
    assert result["failed_attempts_24h"] == 3


def test_dashboard_stats_successful_2fa_not_counted_as_failure(tmp_db):
    conn = database.get_db()
    recent = _fmt(_now() - timedelta(hours=1))
    conn.execute(
        "INSERT INTO audit_log (client_id, action, status, ip_address, timestamp) "
        "VALUES (?, ?, ?, ?, ?)",
        ("alice", "2FA_VERIFY", "success", "10.1.1.1", recent),
    )
    conn.commit()
    conn.close()

    result = asyncio.run(console.get_dashboard_stats(client_id="admin"))
    assert result["failed_attempts_24h"] == 0


def test_dashboard_stats_bandwidth_24h_sums_today(tmp_db):
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    conn = database.get_db()
    conn.execute(
        "INSERT INTO bandwidth_usage (client_id, scan_date, rx_bytes, tx_bytes) "
        "VALUES (?, ?, ?, ?)",
        ("alice", today, 1_000_000, 500_000),
    )
    conn.execute(
        "INSERT INTO bandwidth_usage (client_id, scan_date, rx_bytes, tx_bytes) "
        "VALUES (?, ?, ?, ?)",
        ("bob", today, 2_000_000, 1_000_000),
    )
    conn.commit()
    conn.close()

    result = asyncio.run(console.get_dashboard_stats(client_id="admin"))
    # today_total = 4_500_000; bandwidth_24h >= that (adds fraction of yesterday)
    assert result["bandwidth_24h"] >= 4_500_000


def test_dashboard_stats_new_users_24h(tmp_db):
    conn = database.get_db()
    # created_at defaults to current timestamp — both rows are "new"
    conn.execute("INSERT INTO users (client_id, enabled) VALUES ('new1', 1)")
    conn.execute("INSERT INTO users (client_id, enabled) VALUES ('new2', 1)")
    conn.commit()
    conn.close()

    result = asyncio.run(console.get_dashboard_stats(client_id="admin"))
    assert result["new_users_24h"] == 2


def test_dashboard_stats_error_suffix_status_counted_as_failure(tmp_db):
    """status values matching 'error_%' must be flagged as security alerts."""
    conn = database.get_db()
    recent = _fmt(_now() - timedelta(minutes=5))
    conn.execute(
        "INSERT INTO audit_log (client_id, action, status, ip_address, timestamp) "
        "VALUES (?, ?, ?, ?, ?)",
        ("alice", "2FA_VERIFY", "error_db", "10.1.1.1", recent),
    )
    conn.commit()
    conn.close()

    result = asyncio.run(console.get_dashboard_stats(client_id="admin"))
    assert result["failed_attempts_24h"] == 1


# ---------------------------------------------------------------------------
# GET /api/console/activity-metrics
# ---------------------------------------------------------------------------

def test_activity_metrics_empty_db(tmp_db):
    result = asyncio.run(console.get_activity_metrics(client_id="admin"))
    assert result["total_logs"] == 0
    assert result["oldest_log"] is None
    assert result["newest_log"] is None
    assert "retention_days" in result
    assert result["deleted_last_run"] == 0


def test_activity_metrics_counts_all_logs(tmp_db):
    conn = database.get_db()
    for i in range(4):
        conn.execute(
            "INSERT INTO activity_log "
            "(timestamp, client_id, direction, protocol, src_ip, src_port, "
            "dst_ip, dst_port, raw_line, line_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("2026-06-01 10:00:00", "alice", "OUT", "TCP",
             "10.1.1.1", "12345", "1.2.3.4", "443",
             "[WS] line", f"hash-{i}"),
        )
    conn.commit()
    conn.close()

    result = asyncio.run(console.get_activity_metrics(client_id="admin"))
    assert result["total_logs"] == 4


def test_activity_metrics_oldest_and_newest(tmp_db):
    conn = database.get_db()
    for ts, h in [("2026-05-01 00:00:00", "h1"), ("2026-06-01 00:00:00", "h2")]:
        conn.execute(
            "INSERT INTO activity_log "
            "(timestamp, client_id, direction, protocol, src_ip, src_port, "
            "dst_ip, dst_port, raw_line, line_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ts, "alice", "OUT", "TCP", "10.1.1.1", "1234", "8.8.8.8", "53", "l", h),
        )
    conn.commit()
    conn.close()

    result = asyncio.run(console.get_activity_metrics(client_id="admin"))
    assert result["oldest_log"] == "2026-05-01 00:00:00"
    assert result["newest_log"] == "2026-06-01 00:00:00"
