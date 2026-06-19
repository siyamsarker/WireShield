"""Tests for session expiry enforcement and the post-disconnect bypass fix.

Key scenarios:
  - console access granted only when session is valid AND non-expired
  - remove_client_by_id deletes sessions → console access denied immediately after
  - no console_access flag → denied even with live session
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

from fastapi import HTTPException
from app.core import database
from app.core.security import hash_session_token, remove_client_by_id
from app.routers.console import _check_console_access


# ---------------------------------------------------------------------------
# Minimal Request/Client stubs
# ---------------------------------------------------------------------------

class _FakeClient:
    def __init__(self, host):
        self.host = host


class _FakeRequest:
    def __init__(self, host):
        self.client = _FakeClient(host)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_user(conn, client_id, wg_ip, console_access=True):
    conn.execute(
        "INSERT INTO users (client_id, wg_ipv4, enabled, console_access) VALUES (?, ?, ?, ?)",
        (client_id, wg_ip, 1, 1 if console_access else 0),
    )


def _make_session(conn, client_id, wg_ip, expired=False):
    if expired:
        expires = (datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    else:
        expires = (datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "INSERT INTO sessions (client_id, session_token, expires_at, device_ip) "
        "VALUES (?, ?, ?, ?)",
        (client_id, hash_session_token("tok"), expires, wg_ip),
    )


# ---------------------------------------------------------------------------
# _check_console_access
# ---------------------------------------------------------------------------

def test_console_access_granted_with_live_session(tmp_db):
    conn = database.get_db()
    _make_user(conn, "admin", "10.66.66.2")
    _make_session(conn, "admin", "10.66.66.2")
    conn.commit()
    conn.close()

    result = asyncio.run(_check_console_access(_FakeRequest("10.66.66.2")))
    assert result == "admin"


def test_console_access_denied_expired_session(tmp_db):
    """Bug-fix regression: expired session must deny even if console_access=1."""
    conn = database.get_db()
    _make_user(conn, "admin", "10.66.66.2")
    _make_session(conn, "admin", "10.66.66.2", expired=True)
    conn.commit()
    conn.close()

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(_check_console_access(_FakeRequest("10.66.66.2")))
    assert exc_info.value.status_code == 403


def test_console_access_denied_no_session(tmp_db):
    conn = database.get_db()
    _make_user(conn, "admin", "10.66.66.2")
    # No session inserted
    conn.commit()
    conn.close()

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(_check_console_access(_FakeRequest("10.66.66.2")))
    assert exc_info.value.status_code == 403


def test_console_access_denied_no_console_flag(tmp_db):
    conn = database.get_db()
    _make_user(conn, "regular", "10.66.66.5", console_access=False)
    _make_session(conn, "regular", "10.66.66.5")
    conn.commit()
    conn.close()

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(_check_console_access(_FakeRequest("10.66.66.5")))
    assert exc_info.value.status_code == 403


def test_console_access_denied_unknown_ip(tmp_db):
    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(_check_console_access(_FakeRequest("172.16.0.99")))
    assert exc_info.value.status_code == 403


# ---------------------------------------------------------------------------
# Post-disconnect bypass fix (commit 59294fe)
# ---------------------------------------------------------------------------

def test_console_access_denied_after_remove_client(tmp_db):
    """After remove_client_by_id, console must be immediately inaccessible.

    Before the fix: session row persisted after ipset removal, so a reconnected
    client could bypass 2FA and reach /console with the stale session token.
    After the fix: remove_client_by_id deletes the session row in the same DB
    transaction, closing the bypass window.
    """
    conn = database.get_db()
    _make_user(conn, "victim", "10.66.66.7")
    _make_session(conn, "victim", "10.66.66.7")
    conn.commit()
    conn.close()

    # Confirm access is granted before disconnect
    result = asyncio.run(_check_console_access(_FakeRequest("10.66.66.7")))
    assert result == "victim"

    # Simulate WireGuard monitor detecting disconnect
    remove_client_by_id("victim")

    # Access must now be denied because the session row is gone
    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(_check_console_access(_FakeRequest("10.66.66.7")))
    assert exc_info.value.status_code == 403


def test_multiple_sessions_all_deleted_on_remove(tmp_db):
    """All sessions for a client are deleted, not just the most recent."""
    conn = database.get_db()
    _make_user(conn, "multi", "10.66.66.9")
    expires = (datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    for i in range(3):
        conn.execute(
            "INSERT INTO sessions (client_id, session_token, expires_at, device_ip) "
            "VALUES (?, ?, ?, ?)",
            ("multi", hash_session_token(f"tok-{i}"), expires, "10.66.66.9"),
        )
    conn.commit()
    conn.close()

    remove_client_by_id("multi")

    conn = database.get_db()
    count = conn.execute(
        "SELECT COUNT(*) FROM sessions WHERE client_id = 'multi'"
    ).fetchone()[0]
    conn.close()
    assert count == 0
