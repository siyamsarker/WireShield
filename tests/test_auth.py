"""Integration tests for the auth router: 2FA setup, verify, validate-session."""
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pyotp
import pytest

os.environ.setdefault("WS_2FA_SECRET_KEY", "wireshield-test-secret-key")
os.environ.setdefault("WS_CSRF_DISABLE", "1")
service_root = Path(__file__).parent.parent / "console-server"
if str(service_root) not in sys.path:
    sys.path.insert(0, str(service_root))

from fastapi.testclient import TestClient
from app.main import app
from app.core import database
from app.core.security import generate_session_token, hash_session_token, rate_limiter

# TestClient without context manager → lifespan (init_db, background tasks) does not run.
# The tmp_db fixture calls init_db() and patches AUTH_DB_PATH before any request.
_client = TestClient(app)


@pytest.fixture
def client(tmp_db):
    rate_limiter._hits.clear()
    return _client


# ---------------------------------------------------------------------------
# POST /api/setup-start
# ---------------------------------------------------------------------------

def test_setup_start_creates_user_and_returns_qr(client, tmp_db):
    resp = client.post("/api/setup-start", data={"client_id": "newuser"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True
    assert body["qr_code"].startswith("data:image/png;base64,")
    assert "secret" in body

    conn = database.get_db()
    row = conn.execute(
        "SELECT totp_secret FROM users WHERE client_id = 'newuser'"
    ).fetchone()
    conn.close()
    assert row is not None and row[0] is not None


def test_setup_start_already_configured_returns_400(client, tmp_db):
    conn = database.get_db()
    conn.execute(
        "INSERT INTO users (client_id, totp_secret, enabled) VALUES (?, ?, ?)",
        ("configured", "JBSWY3DPEHPK3PXP", 1),
    )
    conn.commit()
    conn.close()

    resp = client.post("/api/setup-start", data={"client_id": "configured"})
    assert resp.status_code == 400
    assert resp.json()["detail"] == "already_configured"


def test_setup_start_ip_mismatch_rejected(client, tmp_db):
    """A user whose wg_ipv4 is not 'testclient' must get 403."""
    conn = database.get_db()
    conn.execute(
        "INSERT INTO users (client_id, wg_ipv4, enabled) VALUES (?, ?, ?)",
        ("alice", "10.66.66.2", 1),
    )
    conn.commit()
    conn.close()

    resp = client.post("/api/setup-start", data={"client_id": "alice"})
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# POST /api/setup-verify
# ---------------------------------------------------------------------------

def test_setup_verify_creates_session(client, tmp_db):
    secret = pyotp.random_base32()
    conn = database.get_db()
    # wg_ipv4 = "testclient" to match TestClient's reported host
    conn.execute(
        "INSERT INTO users (client_id, totp_secret, enabled, wg_ipv4) VALUES (?, ?, ?, ?)",
        ("bob", secret, 0, "testclient"),
    )
    conn.commit()
    conn.close()

    code = pyotp.TOTP(secret).now()
    resp = client.post("/api/setup-verify", data={"client_id": "bob", "code": code})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["success"] is True
    assert "session_token" in body

    conn = database.get_db()
    count = conn.execute(
        "SELECT COUNT(*) FROM sessions WHERE client_id = 'bob'"
    ).fetchone()[0]
    conn.close()
    assert count == 1


def test_setup_verify_invalid_code_returns_401(client, tmp_db):
    secret = pyotp.random_base32()
    conn = database.get_db()
    conn.execute(
        "INSERT INTO users (client_id, totp_secret, enabled, wg_ipv4) VALUES (?, ?, ?, ?)",
        ("carol", secret, 0, "testclient"),
    )
    conn.commit()
    conn.close()

    with patch("app.routers.auth.pyotp.TOTP") as mock_cls:
        mock_cls.return_value.verify.return_value = False
        resp = client.post("/api/setup-verify", data={"client_id": "carol", "code": "000000"})
    assert resp.status_code == 401


def test_setup_verify_user_not_found_returns_404(client, tmp_db):
    resp = client.post("/api/setup-verify", data={"client_id": "nobody", "code": "123456"})
    # verify_client_ip allows unknown user; totp_secret lookup returns 404
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# POST /api/verify
# ---------------------------------------------------------------------------

def test_verify_creates_session(client, tmp_db):
    secret = pyotp.random_base32()
    conn = database.get_db()
    conn.execute(
        "INSERT INTO users (client_id, totp_secret, enabled, wg_ipv4) VALUES (?, ?, ?, ?)",
        ("dave", secret, 1, "testclient"),
    )
    conn.commit()
    conn.close()

    code = pyotp.TOTP(secret).now()
    resp = client.post("/api/verify", data={"client_id": "dave", "code": code})
    assert resp.status_code == 200, resp.text
    assert resp.json()["success"] is True

    conn = database.get_db()
    count = conn.execute(
        "SELECT COUNT(*) FROM sessions WHERE client_id = 'dave'"
    ).fetchone()[0]
    conn.close()
    assert count == 1


def test_verify_invalidates_old_sessions(client, tmp_db):
    """Each successful verify wipes previous sessions."""
    secret = pyotp.random_base32()
    conn = database.get_db()
    conn.execute(
        "INSERT INTO users (client_id, totp_secret, enabled, wg_ipv4) VALUES (?, ?, ?, ?)",
        ("eve", secret, 1, "testclient"),
    )
    old_exp = (datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "INSERT INTO sessions (client_id, session_token, expires_at, device_ip) "
        "VALUES (?, ?, ?, ?)",
        ("eve", hash_session_token("old-tok"), old_exp, "testclient"),
    )
    conn.commit()
    conn.close()

    code = pyotp.TOTP(secret).now()
    resp = client.post("/api/verify", data={"client_id": "eve", "code": code})
    assert resp.status_code == 200

    conn = database.get_db()
    count = conn.execute(
        "SELECT COUNT(*) FROM sessions WHERE client_id = 'eve'"
    ).fetchone()[0]
    conn.close()
    # Old session deleted, new one created → exactly 1
    assert count == 1


def test_verify_totp_replay_rejected(client, tmp_db):
    secret = pyotp.random_base32()
    conn = database.get_db()
    conn.execute(
        "INSERT INTO users (client_id, totp_secret, enabled, wg_ipv4) VALUES (?, ?, ?, ?)",
        ("frank", secret, 1, "testclient"),
    )
    conn.commit()
    conn.close()

    code = pyotp.TOTP(secret).now()

    resp1 = client.post("/api/verify", data={"client_id": "frank", "code": code})
    assert resp1.status_code == 200

    rate_limiter._hits.clear()
    resp2 = client.post("/api/verify", data={"client_id": "frank", "code": code})
    assert resp2.status_code == 401


def test_verify_not_configured_returns_403(client, tmp_db):
    conn = database.get_db()
    conn.execute(
        "INSERT INTO users (client_id, enabled, wg_ipv4) VALUES (?, ?, ?)",
        ("ghost", 0, "testclient"),
    )
    conn.commit()
    conn.close()

    resp = client.post("/api/verify", data={"client_id": "ghost", "code": "123456"})
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# POST /api/validate-session
# ---------------------------------------------------------------------------

def test_validate_session_valid(client, tmp_db):
    token = generate_session_token()
    expires = (datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    conn = database.get_db()
    conn.execute("INSERT INTO users (client_id, enabled) VALUES (?, ?)", ("grace", 1))
    conn.execute(
        "INSERT INTO sessions (client_id, session_token, expires_at, device_ip) "
        "VALUES (?, ?, ?, ?)",
        ("grace", hash_session_token(token), expires, "testclient"),
    )
    conn.commit()
    conn.close()

    resp = client.post(
        "/api/validate-session",
        data={"client_id": "grace", "session_token": token},
    )
    assert resp.status_code == 200
    assert resp.json()["valid"] is True


def test_validate_session_expired_returns_401(client, tmp_db):
    token = generate_session_token()
    expired = (datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    conn = database.get_db()
    conn.execute("INSERT INTO users (client_id, enabled) VALUES (?, ?)", ("henry", 1))
    conn.execute(
        "INSERT INTO sessions (client_id, session_token, expires_at, device_ip) "
        "VALUES (?, ?, ?, ?)",
        ("henry", hash_session_token(token), expired, "testclient"),
    )
    conn.commit()
    conn.close()

    resp = client.post(
        "/api/validate-session",
        data={"client_id": "henry", "session_token": token},
    )
    assert resp.status_code == 401


def test_validate_session_wrong_token_returns_401(client, tmp_db):
    token = generate_session_token()
    expires = (datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    conn = database.get_db()
    conn.execute("INSERT INTO users (client_id, enabled) VALUES (?, ?)", ("ivan", 1))
    conn.execute(
        "INSERT INTO sessions (client_id, session_token, expires_at, device_ip) "
        "VALUES (?, ?, ?, ?)",
        ("ivan", hash_session_token(token), expires, "testclient"),
    )
    conn.commit()
    conn.close()

    resp = client.post(
        "/api/validate-session",
        data={"client_id": "ivan", "session_token": "forged-token"},
    )
    assert resp.status_code == 401
