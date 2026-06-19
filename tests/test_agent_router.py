"""Tests for the agent-facing router endpoints: enroll, heartbeat, and
revocation-check.

WireGuard key generation and wg(8) invocations are mocked so these tests run
without root privileges or WireGuard installed.
"""
import hashlib
import os
import secrets
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

os.environ.setdefault("WS_2FA_SECRET_KEY", "wireshield-test-secret-key")
os.environ.setdefault("WS_CSRF_DISABLE", "1")
service_root = Path(__file__).parent.parent / "console-server"
if str(service_root) not in sys.path:
    sys.path.insert(0, str(service_root))

from fastapi.testclient import TestClient
from app.main import app
from app.core import database
from app.core.security import rate_limiter

_client = TestClient(app)


@pytest.fixture
def client(tmp_db):
    rate_limiter._hits.clear()
    return _client


# ---------------------------------------------------------------------------
# POST /api/agents/enroll
# ---------------------------------------------------------------------------

def test_enroll_missing_token_returns_401(client, tmp_db):
    """enroll_agent raises ValueError with 'token' in msg → 401."""
    with patch(
        "app.core.agents.enroll_agent",
        side_effect=ValueError("Invalid, expired, or already-used enrollment token"),
    ):
        resp = client.post(
            "/api/agents/enroll",
            json={"token": "bad-token", "public_key": "pubkey=="},
        )
    assert resp.status_code == 401
    assert "enrollment token" in resp.json()["detail"].lower()


def test_enroll_valid_token_returns_config(client, tmp_db):
    """A good enrollment token returns WireGuard config fields."""
    mock_result = {
        "id": 1,
        "name": "edge-01",
        "wg_ipv4": "10.99.0.2",
        "preshared_key": "psk==",
        "server_public_key": "srv_pub==",
        "endpoint": "vpn.example.com:51820",
        "agent_allowed_ips": "10.0.0.0/8",
        "advertised_cidrs": ["192.168.1.0/24"],
        "config": "[Interface]\nPrivateKey=...",
        "heartbeat_secret": "hb_secret_abc",
    }
    with patch("app.core.agents.enroll_agent", return_value=mock_result) as mock_enroll:
        resp = client.post(
            "/api/agents/enroll",
            json={
                "token": "valid_tok",
                "public_key": "agent_pub==",
                "hostname": "myhost",
                "advertised_cidrs": ["192.168.1.0/24"],
            },
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True
    assert body["agent_id"] == 1
    assert body["wg_ipv4"] == "10.99.0.2"
    assert "config" in body
    assert "heartbeat_secret" in body
    mock_enroll.assert_called_once()


def test_enroll_duplicate_key_returns_400(client, tmp_db):
    """enroll_agent raises ValueError (non-token, e.g. duplicate key) → 400."""
    with patch("app.core.agents.enroll_agent", side_effect=ValueError("duplicate public key")):
        resp = client.post(
            "/api/agents/enroll",
            json={"token": "tok", "public_key": "dup=="},
        )
    assert resp.status_code == 400


def test_enroll_runtime_error_returns_500(client, tmp_db):
    """enroll_agent raises RuntimeError (wg syscall) → 500."""
    with patch("app.core.agents.enroll_agent", side_effect=RuntimeError("wg add peer failed")):
        resp = client.post(
            "/api/agents/enroll",
            json={"token": "tok", "public_key": "pk=="},
        )
    assert resp.status_code == 500


# ---------------------------------------------------------------------------
# POST /api/agents/heartbeat
# ---------------------------------------------------------------------------

def _insert_enrolled_agent(tmp_db, secret: str) -> int:
    """Insert an enrolled agent row and return its id."""
    secret_hash = hashlib.sha256(secret.encode()).hexdigest()
    conn = database.get_db()
    conn.execute(
        "INSERT INTO agents "
        "(name, status, wg_ipv4, public_key, preshared_key, "
        "heartbeat_secret_hash, created_by) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("edge-01", "enrolled", "10.99.0.2", "pubkey==",
         "psk_val", secret_hash, "admin"),
    )
    conn.commit()
    agent_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()
    return agent_id


def test_heartbeat_missing_auth_returns_403(client, tmp_db):
    resp = client.post("/api/agents/heartbeat", json={})
    assert resp.status_code == 403


def test_heartbeat_bad_token_returns_403(client, tmp_db):
    resp = client.post(
        "/api/agents/heartbeat",
        json={},
        headers={"Authorization": "Bearer wrong_secret"},
    )
    assert resp.status_code == 403


def test_heartbeat_valid_token_records_heartbeat(client, tmp_db):
    secret = secrets.token_urlsafe(32)
    agent_id = _insert_enrolled_agent(tmp_db, secret)

    mock_result = {"agent_id": agent_id, "advertised_cidrs": [], "lan_interface": None}
    with patch("app.core.agents.record_heartbeat", return_value=mock_result) as mock_hb:
        resp = client.post(
            "/api/agents/heartbeat",
            json={"agent_version": "1.0.0", "rx_bytes": 1024, "tx_bytes": 512},
            headers={"Authorization": f"Bearer {secret}"},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True
    mock_hb.assert_called_once_with(
        auth_token=secret,
        source_ip="testclient",
        agent_version="1.0.0",
        rx_bytes=1024,
        tx_bytes=512,
    )


def test_heartbeat_revoked_agent_returns_403(client, tmp_db):
    """An agent whose status is 'revoked' must be rejected even with a correct token."""
    secret = secrets.token_urlsafe(32)
    secret_hash = hashlib.sha256(secret.encode()).hexdigest()
    conn = database.get_db()
    conn.execute(
        "INSERT INTO agents "
        "(name, status, wg_ipv4, public_key, preshared_key, "
        "heartbeat_secret_hash, created_by) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("revoked-edge", "revoked", "10.99.0.3", "pk==",
         "ph", secret_hash, "admin"),
    )
    conn.commit()
    conn.close()

    resp = client.post(
        "/api/agents/heartbeat",
        json={},
        headers={"Authorization": f"Bearer {secret}"},
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# GET /api/agents/revocation-check
# ---------------------------------------------------------------------------

def test_revocation_check_unknown_agent_returns_403(client, tmp_db):
    """No agent with this secret → 403 (same as bad token — no info leakage)."""
    resp = client.get(
        "/api/agents/revocation-check",
        headers={"Authorization": "Bearer unknown_secret"},
    )
    assert resp.status_code == 403


def test_revocation_check_enrolled_agent_returns_ok(client, tmp_db):
    secret = secrets.token_urlsafe(32)
    _insert_enrolled_agent(tmp_db, secret)

    resp = client.get(
        "/api/agents/revocation-check",
        headers={"Authorization": f"Bearer {secret}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body.get("revoked") is False


def test_revocation_check_revoked_agent_returns_403(client, tmp_db):
    """_verify_agent_request rejects non-enrolled agents — a revoked agent
    cannot call revocation-check and receives 403."""
    secret = secrets.token_urlsafe(32)
    secret_hash = hashlib.sha256(secret.encode()).hexdigest()
    conn = database.get_db()
    conn.execute(
        "INSERT INTO agents "
        "(name, status, wg_ipv4, public_key, preshared_key, "
        "heartbeat_secret_hash, created_by) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("revoked-agent", "revoked", "10.99.0.5", "pk5==",
         "ph", secret_hash, "admin"),
    )
    conn.commit()
    conn.close()

    resp = client.get(
        "/api/agents/revocation-check",
        headers={"Authorization": f"Bearer {secret}"},
    )
    assert resp.status_code == 403
