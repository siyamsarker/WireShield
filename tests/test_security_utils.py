"""Tests for security utilities: session tokens, CSRF, TOTP replay, IP verification,
remove_client_by_id session cleanup, and audit_log insertion."""
import hashlib
import hmac
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

os.environ.setdefault("WS_2FA_SECRET_KEY", "wireshield-test-secret-key")
service_root = Path(__file__).parent.parent / "console-server"
if str(service_root) not in sys.path:
    sys.path.insert(0, str(service_root))

from app.core import database
from app.core.security import (
    audit_log,
    check_and_mark_totp_code,
    generate_session_token,
    hash_session_token,
    remove_client_by_id,
    verify_client_ip,
    verify_session_token,
)


# ---------------------------------------------------------------------------
# Session token helpers
# ---------------------------------------------------------------------------

def test_generate_session_token_is_nonempty():
    token = generate_session_token()
    assert isinstance(token, str) and len(token) >= 32


def test_hash_session_token_deterministic():
    token = "fixed-test-token"
    assert hash_session_token(token) == hash_session_token(token)
    assert len(hash_session_token(token)) == 64  # SHA-256 hex digest


def test_verify_session_token_correct():
    token = generate_session_token()
    stored = hash_session_token(token)
    assert verify_session_token(token, stored) is True


def test_verify_session_token_wrong_token():
    token = generate_session_token()
    stored = hash_session_token(token)
    assert verify_session_token("wrong-token", stored) is False


# ---------------------------------------------------------------------------
# CSRF token
# ---------------------------------------------------------------------------

def test_csrf_token_for_ip_deterministic():
    from app.routers.console import _csrf_token_for_ip
    from app.core.config import SECRET_KEY
    ip = "10.66.66.2"
    expected = hmac.new(SECRET_KEY.encode(), ip.encode(), hashlib.sha256).hexdigest()
    assert _csrf_token_for_ip(ip) == expected


def test_csrf_token_differs_by_ip():
    from app.routers.console import _csrf_token_for_ip
    assert _csrf_token_for_ip("10.66.66.2") != _csrf_token_for_ip("10.66.66.3")


def test_csrf_disabled_env_var():
    from app.routers.console import _csrf_disabled
    original = os.environ.get("WS_CSRF_DISABLE")
    try:
        os.environ["WS_CSRF_DISABLE"] = "1"
        assert _csrf_disabled() is True
        os.environ["WS_CSRF_DISABLE"] = "0"
        assert _csrf_disabled() is False
    finally:
        if original is None:
            os.environ.pop("WS_CSRF_DISABLE", None)
        else:
            os.environ["WS_CSRF_DISABLE"] = original


# ---------------------------------------------------------------------------
# TOTP replay prevention
# ---------------------------------------------------------------------------

def test_totp_first_use_accepted(tmp_db):
    assert check_and_mark_totp_code("alice", "123456") is True


def test_totp_replay_rejected(tmp_db):
    assert check_and_mark_totp_code("alice", "999999") is True
    assert check_and_mark_totp_code("alice", "999999") is False


def test_totp_different_clients_independent(tmp_db):
    """Same code for different clients is independently accepted."""
    assert check_and_mark_totp_code("alice", "111111") is True
    assert check_and_mark_totp_code("bob", "111111") is True


def test_totp_stale_code_reusable(tmp_db):
    """A code older than the replay window is pruned and can be reused."""
    conn = database.get_db()
    stale_ts = (datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=100)).strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "INSERT INTO totp_used_codes (client_id, code, used_at) VALUES (?, ?, ?)",
        ("charlie", "000000", stale_ts),
    )
    conn.commit()
    conn.close()
    # Pruning step removes the stale row → INSERT succeeds → True
    assert check_and_mark_totp_code("charlie", "000000") is True


def test_totp_within_window_rejected(tmp_db):
    """A code used 30 s ago (inside 90 s window) is still rejected as replay."""
    conn = database.get_db()
    recent_ts = (datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=30)).strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "INSERT INTO totp_used_codes (client_id, code, used_at) VALUES (?, ?, ?)",
        ("diana", "555555", recent_ts),
    )
    conn.commit()
    conn.close()
    assert check_and_mark_totp_code("diana", "555555") is False


# ---------------------------------------------------------------------------
# verify_client_ip
# ---------------------------------------------------------------------------

def test_verify_client_ip_unknown_client_allowed(tmp_db):
    """Unknown client with any IP is allowed (first-time setup path)."""
    assert verify_client_ip("new-user", "10.66.66.50") is True


def test_verify_client_ip_ip_belongs_to_other_user(tmp_db):
    """IP already claimed by a different user → reject."""
    conn = database.get_db()
    conn.execute(
        "INSERT INTO users (client_id, wg_ipv4, enabled) VALUES (?, ?, ?)",
        ("alice", "10.66.66.2", 1),
    )
    conn.commit()
    conn.close()
    assert verify_client_ip("bob", "10.66.66.2") is False


def test_verify_client_ip_matches_registered(tmp_db):
    conn = database.get_db()
    conn.execute(
        "INSERT INTO users (client_id, wg_ipv4, enabled) VALUES (?, ?, ?)",
        ("alice", "10.66.66.2", 1),
    )
    conn.commit()
    conn.close()
    assert verify_client_ip("alice", "10.66.66.2") is True


def test_verify_client_ip_mismatch_rejected(tmp_db):
    conn = database.get_db()
    conn.execute(
        "INSERT INTO users (client_id, wg_ipv4, enabled) VALUES (?, ?, ?)",
        ("alice", "10.66.66.2", 1),
    )
    conn.commit()
    conn.close()
    assert verify_client_ip("alice", "10.66.66.99") is False


def test_verify_client_ip_no_ip_on_file_allowed(tmp_db):
    """User exists but has no registered IP → allow (new setup edge case)."""
    conn = database.get_db()
    conn.execute(
        "INSERT INTO users (client_id, enabled) VALUES (?, ?)",
        ("new-setup", 0),
    )
    conn.commit()
    conn.close()
    assert verify_client_ip("new-setup", "10.66.66.5") is True


def test_verify_client_ip_v6_match(tmp_db):
    conn = database.get_db()
    conn.execute(
        "INSERT INTO users (client_id, wg_ipv6, enabled) VALUES (?, ?, ?)",
        ("alice", "fd86:ea04::2", 1),
    )
    conn.commit()
    conn.close()
    assert verify_client_ip("alice", "fd86:ea04::2") is True


# ---------------------------------------------------------------------------
# remove_client_by_id — session cleanup regression test (commit 59294fe)
# ---------------------------------------------------------------------------

def test_remove_client_by_id_deletes_session_rows(tmp_db):
    """Regression: disconnect must delete session rows, not only clear the ipset.

    Before the fix, remove_client_by_id only called `ipset del`; the session
    row remained valid, allowing a reconnected client to reach /console without
    re-authenticating (post-disconnect 2FA bypass).
    """
    conn = database.get_db()
    conn.execute(
        "INSERT INTO users (client_id, wg_ipv4, enabled) VALUES (?, ?, ?)",
        ("alice", "10.66.66.2", 1),
    )
    expires = (datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "INSERT INTO sessions (client_id, session_token, expires_at, device_ip) "
        "VALUES (?, ?, ?, ?)",
        ("alice", hash_session_token("tok"), expires, "10.66.66.2"),
    )
    conn.commit()
    conn.close()

    remove_client_by_id("alice")

    conn = database.get_db()
    count = conn.execute(
        "SELECT COUNT(*) FROM sessions WHERE client_id = 'alice'"
    ).fetchone()[0]
    conn.close()
    assert count == 0, "Session rows must be deleted when client is removed"


def test_remove_client_by_id_unknown_client_safe(tmp_db):
    """Calling remove_client_by_id for an unknown client must not raise."""
    remove_client_by_id("ghost-user")  # must not raise


def test_remove_client_by_id_does_not_touch_other_clients_sessions(tmp_db):
    """Only the target client's sessions are removed, not other clients'."""
    conn = database.get_db()
    conn.execute(
        "INSERT INTO users (client_id, wg_ipv4, enabled) VALUES (?, ?, ?)",
        ("alice", "10.66.66.2", 1),
    )
    conn.execute(
        "INSERT INTO users (client_id, wg_ipv4, enabled) VALUES (?, ?, ?)",
        ("bob", "10.66.66.3", 1),
    )
    expires = (datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "INSERT INTO sessions (client_id, session_token, expires_at, device_ip) "
        "VALUES (?, ?, ?, ?)",
        ("alice", hash_session_token("tok-a"), expires, "10.66.66.2"),
    )
    conn.execute(
        "INSERT INTO sessions (client_id, session_token, expires_at, device_ip) "
        "VALUES (?, ?, ?, ?)",
        ("bob", hash_session_token("tok-b"), expires, "10.66.66.3"),
    )
    conn.commit()
    conn.close()

    remove_client_by_id("alice")

    conn = database.get_db()
    bob_count = conn.execute(
        "SELECT COUNT(*) FROM sessions WHERE client_id = 'bob'"
    ).fetchone()[0]
    conn.close()
    assert bob_count == 1, "Bob's session must not be removed"


# ---------------------------------------------------------------------------
# audit_log
# ---------------------------------------------------------------------------

def test_audit_log_inserts_row(tmp_db):
    audit_log("alice", "2FA_VERIFY", "success", "10.66.66.2")
    conn = database.get_db()
    row = conn.execute(
        "SELECT action, status FROM audit_log WHERE client_id = 'alice'"
    ).fetchone()
    conn.close()
    assert row is not None
    assert row[0] == "2FA_VERIFY"
    assert row[1] == "success"


def test_audit_log_accepts_null_client(tmp_db):
    """audit_log must not raise when client_id is None."""
    audit_log(None, "HEALTH_CHECK", "ok", "127.0.0.1")
    conn = database.get_db()
    count = conn.execute(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'HEALTH_CHECK'"
    ).fetchone()[0]
    conn.close()
    assert count == 1
