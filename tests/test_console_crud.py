"""Tests for console CRUD endpoints: agent create/list/get/patch/delete and
user create/delete.  WireGuard and ipset side-effects are mocked so tests run
without root privileges or a real WireGuard installation.

All async endpoint functions are called directly (bypassing FastAPI dependency
injection) following the pattern used in test_console_api.py.
"""
import asyncio
import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

os.environ.setdefault("WS_2FA_SECRET_KEY", "wireshield-test-secret-key")
os.environ.setdefault("WS_CSRF_DISABLE", "1")
service_root = Path(__file__).parent.parent / "console-server"
if str(service_root) not in sys.path:
    sys.path.insert(0, str(service_root))

from fastapi import HTTPException
from app.core import database
from app.routers import console


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _FakeClient:
    host = "testclient"


class _FakeRequest:
    client = _FakeClient()
    headers: dict = {}


def _fake_req():
    return _FakeRequest()


def _insert_agent(conn, name="edge-01", status="enrolled", wg_ipv4="10.99.0.2"):
    conn.execute(
        "INSERT INTO agents "
        "(name, description, status, wg_ipv4, public_key, "
        "preshared_key, heartbeat_secret_hash, created_by) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (name, "desc", status, wg_ipv4, "pubkey", "psk_val", "hb_h", "admin"),
    )
    conn.commit()
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


# ---------------------------------------------------------------------------
# Agent list
# ---------------------------------------------------------------------------

def test_list_agents_empty_db(tmp_db):
    result = asyncio.run(console.list_agents_endpoint(include_revoked=False, client_id="admin"))
    assert result["agents"] == []
    assert result["count"] == 0


def test_list_agents_returns_enrolled(tmp_db):
    conn = database.get_db()
    _insert_agent(conn, name="edge-01", status="enrolled")
    conn.close()

    result = asyncio.run(console.list_agents_endpoint(include_revoked=False, client_id="admin"))
    assert result["count"] == 1
    assert result["agents"][0]["name"] == "edge-01"
    assert result["agents"][0]["status"] == "enrolled"


def test_list_agents_returns_pending(tmp_db):
    conn = database.get_db()
    _insert_agent(conn, name="pending-01", status="pending", wg_ipv4="10.99.0.3")
    conn.close()

    result = asyncio.run(console.list_agents_endpoint(include_revoked=False, client_id="admin"))
    assert result["count"] == 1
    assert result["agents"][0]["status"] == "pending"


def test_list_agents_excludes_revoked_by_default(tmp_db):
    conn = database.get_db()
    _insert_agent(conn, name="revoked-01", status="revoked", wg_ipv4="10.99.0.4")
    conn.close()

    result = asyncio.run(console.list_agents_endpoint(include_revoked=False, client_id="admin"))
    assert result["count"] == 0


def test_list_agents_includes_revoked_when_requested(tmp_db):
    conn = database.get_db()
    _insert_agent(conn, name="revoked-01", status="revoked", wg_ipv4="10.99.0.4")
    conn.close()

    result = asyncio.run(console.list_agents_endpoint(include_revoked=True, client_id="admin"))
    assert result["count"] == 1


def test_list_agents_multiple_statuses(tmp_db):
    conn = database.get_db()
    _insert_agent(conn, name="a1", status="enrolled",  wg_ipv4="10.99.0.2")
    _insert_agent(conn, name="a2", status="pending",   wg_ipv4="10.99.0.3")
    _insert_agent(conn, name="a3", status="revoked",   wg_ipv4="10.99.0.4")
    conn.close()

    result_excl = asyncio.run(console.list_agents_endpoint(include_revoked=False, client_id="admin"))
    assert result_excl["count"] == 2

    result_incl = asyncio.run(console.list_agents_endpoint(include_revoked=True, client_id="admin"))
    assert result_incl["count"] == 3


# ---------------------------------------------------------------------------
# Agent get
# ---------------------------------------------------------------------------

def test_get_agent_not_found_raises_404(tmp_db):
    with pytest.raises(HTTPException) as exc:
        asyncio.run(console.get_agent_endpoint(agent_id=9999, client_id="admin"))
    assert exc.value.status_code == 404


def test_get_agent_returns_detail(tmp_db):
    conn = database.get_db()
    agent_id = _insert_agent(conn, name="edge-02", status="enrolled", wg_ipv4="10.99.0.5")
    conn.close()

    result = asyncio.run(console.get_agent_endpoint(agent_id=agent_id, client_id="admin"))
    assert result["name"] == "edge-02"
    assert result["status"] == "enrolled"
    # Enrollment token hash is stored in agent_enrollment_tokens, not agents
    assert "enrollment_token_hash" not in result


# ---------------------------------------------------------------------------
# Agent patch (description + is_restricted)
# ---------------------------------------------------------------------------

def test_patch_agent_description(tmp_db):
    conn = database.get_db()
    agent_id = _insert_agent(conn, name="edge-03", status="enrolled", wg_ipv4="10.99.0.6")
    conn.close()

    body = console.AgentPatchRequest(description="updated desc")
    result = asyncio.run(
        console.patch_agent_endpoint(
            agent_id=agent_id, body=body,
            request=_fake_req(), client_id="admin", _csrf=None,
        )
    )
    assert result["success"] is True
    assert result["agent"]["description"] == "updated desc"


def test_patch_agent_not_found_raises_404(tmp_db):
    body = console.AgentPatchRequest(description="x")
    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            console.patch_agent_endpoint(
                agent_id=9999, body=body,
                request=_fake_req(), client_id="admin", _csrf=None,
            )
        )
    assert exc.value.status_code == 404


def test_patch_agent_cidrs_rejected_for_pending_agent(tmp_db):
    conn = database.get_db()
    agent_id = _insert_agent(conn, name="pending-02", status="pending", wg_ipv4="10.99.0.7")
    conn.close()

    body = console.AgentPatchRequest(advertised_cidrs=["10.0.0.0/8"])
    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            console.patch_agent_endpoint(
                agent_id=agent_id, body=body,
                request=_fake_req(), client_id="admin", _csrf=None,
            )
        )
    assert exc.value.status_code == 400
    assert "enrolled" in exc.value.detail


# ---------------------------------------------------------------------------
# Agent delete (revoke)
# ---------------------------------------------------------------------------

def test_delete_agent_not_found_raises_404(tmp_db):
    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            console.delete_agent_endpoint(
                agent_id=9999, request=_fake_req(), client_id="admin", _csrf=None,
            )
        )
    assert exc.value.status_code == 404


def test_delete_already_revoked_agent_returns_success(tmp_db):
    conn = database.get_db()
    agent_id = _insert_agent(conn, name="already-revoked", status="revoked", wg_ipv4="10.99.0.8")
    conn.close()

    result = asyncio.run(
        console.delete_agent_endpoint(
            agent_id=agent_id, request=_fake_req(), client_id="admin", _csrf=None,
        )
    )
    assert result["success"] is True
    assert result.get("already_revoked") is True


def test_delete_enrolled_agent_calls_revoke(tmp_db):
    conn = database.get_db()
    agent_id = _insert_agent(conn, name="edge-del", status="enrolled", wg_ipv4="10.99.0.9")
    conn.close()

    with patch("app.core.agents.revoke_agent") as mock_revoke:
        mock_revoke.return_value = None
        result = asyncio.run(
            console.delete_agent_endpoint(
                agent_id=agent_id, request=_fake_req(), client_id="admin", _csrf=None,
            )
        )
    mock_revoke.assert_called_once_with(agent_id)
    assert result["success"] is True


# ---------------------------------------------------------------------------
# User create
# ---------------------------------------------------------------------------

def test_create_user_invalid_name_raises_400(tmp_db):
    body = console.UserCreateRequest(client_id="bad name!", expiry_days=None)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(console.create_user(body=body, client_id="admin", _csrf=None))
    assert exc.value.status_code == 400


def test_create_user_invalid_expiry_raises_400(tmp_db):
    body = console.UserCreateRequest(client_id="alice", expiry_days=0)
    with patch("app.core.wireguard.validate_client_name"):
        with pytest.raises(HTTPException) as exc:
            asyncio.run(console.create_user(body=body, client_id="admin", _csrf=None))
    assert exc.value.status_code == 400
    assert "expiry_days" in exc.value.detail


def test_create_user_success(tmp_db):
    mock_result = {"name": "alice", "ipv4": "10.66.66.2", "ipv6": "fd00::2", "expires": None}
    body = console.UserCreateRequest(client_id="alice", expiry_days=None)
    with patch("app.core.wireguard.validate_client_name"):
        with patch("app.core.wireguard.create_client", return_value=mock_result):
            result = asyncio.run(console.create_user(body=body, client_id="admin", _csrf=None))
    assert result["success"] is True
    assert result["name"] == "alice"
    assert result["ipv4"] == "10.66.66.2"


def test_create_user_duplicate_raises_409(tmp_db):
    body = console.UserCreateRequest(client_id="alice", expiry_days=None)
    with patch("app.core.wireguard.validate_client_name"):
        with patch("app.core.wireguard.create_client", side_effect=ValueError("already exists")):
            with pytest.raises(HTTPException) as exc:
                asyncio.run(console.create_user(body=body, client_id="admin", _csrf=None))
    assert exc.value.status_code == 409


# ---------------------------------------------------------------------------
# User delete
# ---------------------------------------------------------------------------

def test_delete_user_refuses_self_deletion(tmp_db):
    with pytest.raises(HTTPException) as exc:
        asyncio.run(console.delete_user(user_client_id="admin", client_id="admin", _csrf=None))
    assert exc.value.status_code == 400
    assert "admin" in exc.value.detail


def test_delete_user_invalid_name_raises_400(tmp_db):
    body_id = "bad name!"
    with pytest.raises(HTTPException) as exc:
        asyncio.run(console.delete_user(user_client_id=body_id, client_id="admin", _csrf=None))
    assert exc.value.status_code == 400


def test_delete_user_not_found_raises_404(tmp_db):
    with patch("app.core.wireguard.validate_client_name"):
        with patch("app.core.wireguard.delete_client", return_value=False):
            with pytest.raises(HTTPException) as exc:
                asyncio.run(console.delete_user(user_client_id="ghost", client_id="admin", _csrf=None))
    assert exc.value.status_code == 404


def test_delete_user_success(tmp_db):
    with patch("app.core.wireguard.validate_client_name"):
        with patch("app.core.wireguard.delete_client", return_value=True):
            result = asyncio.run(
                console.delete_user(user_client_id="bob", client_id="admin", _csrf=None)
            )
    assert result["success"] is True
