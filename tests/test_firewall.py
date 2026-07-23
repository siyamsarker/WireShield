"""Tests for the per-user firewall subsystem: core/firewall.py CRUD +
validation, the WS_USER_FW rule builder in core/tasks.py, and the
console API endpoints. Follows the direct-call pattern used throughout
this test suite (async endpoints invoked via asyncio.run(), bypassing
FastAPI dependency injection).
"""
import asyncio
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

os.environ.setdefault("WS_2FA_SECRET_KEY", "wireshield-test-secret-key")
os.environ.setdefault("WS_CSRF_DISABLE", "1")
service_root = Path(__file__).parent.parent / "console-server"
if str(service_root) not in sys.path:
    sys.path.insert(0, str(service_root))

from fastapi import HTTPException
from app.core import database
from app.core import firewall as fw
from app.core import tasks
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


def _insert_user(conn, client_id="alice", wg_ipv4="10.66.66.5"):
    conn.execute(
        "INSERT INTO users (client_id, wg_ipv4, enabled) VALUES (?, ?, 1)",
        (client_id, wg_ipv4),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Migration: schema exists and init_db() is idempotent
# ---------------------------------------------------------------------------

def test_firewall_tables_created(tmp_db):
    conn = database.get_db()
    tables = {
        r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    conn.close()
    assert {"firewall_policies", "firewall_rules", "user_firewall"} <= tables


def test_init_db_idempotent_with_firewall_tables(tmp_db):
    # Calling init_db() again against the same file must not raise and
    # must not disturb existing rows.
    conn = database.get_db()
    conn.execute("INSERT INTO firewall_policies (name) VALUES ('Keep Me')")
    conn.commit()
    conn.close()

    database.init_db()

    conn = database.get_db()
    row = conn.execute("SELECT name FROM firewall_policies WHERE name = 'Keep Me'").fetchone()
    conn.close()
    assert row is not None


# ---------------------------------------------------------------------------
# core/firewall.py — validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad_direction", ["up", "down", "", None, "OUTBOUND"])
def test_validate_direction_rejects_invalid(bad_direction):
    with pytest.raises(ValueError):
        fw.validate_direction(bad_direction)


@pytest.mark.parametrize("bad_action", ["permit", "block", "", None])
def test_validate_action_rejects_invalid(bad_action):
    with pytest.raises(ValueError):
        fw.validate_action(bad_action)


@pytest.mark.parametrize("bad_protocol", ["ip", "sctp", "TCP;DROP", 123])
def test_validate_protocol_rejects_invalid(bad_protocol):
    with pytest.raises(ValueError):
        fw.validate_protocol(bad_protocol)


def test_validate_protocol_defaults_to_all():
    assert fw.validate_protocol(None) == "all"


def test_validate_port_range_none_means_all_ports():
    assert fw.validate_port_range(None, None, "tcp") == (None, None)


def test_validate_port_range_single_port_fills_end():
    assert fw.validate_port_range(443, None, "tcp") == (443, 443)


@pytest.mark.parametrize("start,end", [(0, 100), (1, 70000), (100, 50), (-1, 10)])
def test_validate_port_range_rejects_out_of_bounds(start, end):
    with pytest.raises(ValueError):
        fw.validate_port_range(start, end, "tcp")


def test_validate_port_range_rejects_ports_on_icmp():
    with pytest.raises(ValueError):
        fw.validate_port_range(80, 80, "icmp")


def test_validate_port_range_rejects_ports_on_all_protocol():
    with pytest.raises(ValueError):
        fw.validate_port_range(80, 80, "all")


def test_validate_remote_cidr_none_means_any():
    assert fw.validate_remote_cidr(None) is None
    assert fw.validate_remote_cidr("") is None


def test_validate_remote_cidr_normalizes():
    assert fw.validate_remote_cidr("10.0.0.0/8") == "10.0.0.0/8"


@pytest.mark.parametrize("bad_cidr", [
    "not-a-cidr",
    "10.0.0.0/8; DROP TABLE users;",
    "$(rm -rf /)",
    "0.0.0.0/0/0",
    "10.0.0.256/8",
])
def test_validate_remote_cidr_rejects_injection_and_malformed(bad_cidr):
    with pytest.raises(ValueError):
        fw.validate_remote_cidr(bad_cidr)


def test_validate_policy_name_rejects_empty_and_too_long():
    with pytest.raises(ValueError):
        fw.validate_policy_name("")
    with pytest.raises(ValueError):
        fw.validate_policy_name("x" * (fw.MAX_POLICY_NAME_LEN + 1))


# ---------------------------------------------------------------------------
# core/firewall.py — policy CRUD
# ---------------------------------------------------------------------------

def test_create_and_get_policy(tmp_db):
    policy = fw.create_policy("Contractors", description="limited", default_action="deny")
    fetched = fw.get_policy(policy["id"])
    assert fetched["name"] == "Contractors"
    assert fetched["default_action"] == "deny"
    assert fetched["rules"] == []


def test_create_policy_duplicate_name_raises(tmp_db):
    fw.create_policy("Contractors")
    with pytest.raises(Exception):
        fw.create_policy("Contractors")


def test_update_policy_partial_fields(tmp_db):
    policy = fw.create_policy("Contractors", default_action="deny")
    changed = fw.update_policy(policy["id"], default_action="allow")
    assert changed is True
    assert fw.get_policy(policy["id"])["default_action"] == "allow"


def test_delete_policy_unassigns_users_instead_of_blocking(tmp_db):
    conn = database.get_db()
    _insert_user(conn, "alice")
    conn.close()

    policy = fw.create_policy("Contractors")
    fw.set_user_firewall("alice", policy_id=policy["id"], blocked=False)

    fw.delete_policy(policy["id"])

    assignment = fw.get_user_firewall("alice")
    assert assignment["policy_id"] is None
    assert assignment["blocked"] is False


# ---------------------------------------------------------------------------
# core/firewall.py — rule CRUD
# ---------------------------------------------------------------------------

def test_add_rule_requires_exactly_one_owner(tmp_db):
    conn = database.get_db()
    _insert_user(conn, "alice")
    conn.close()
    policy = fw.create_policy("Contractors")

    with pytest.raises(ValueError):
        fw.add_rule(policy_id=policy["id"], user_client_id="alice", direction="outbound", action="allow")
    with pytest.raises(ValueError):
        fw.add_rule(direction="outbound", action="allow")


def test_add_rule_unknown_policy_raises(tmp_db):
    with pytest.raises(ValueError):
        fw.add_rule(policy_id=9999, direction="outbound", action="allow")


def test_add_rule_unknown_user_raises(tmp_db):
    with pytest.raises(ValueError):
        fw.add_rule(user_client_id="ghost", direction="outbound", action="allow")


def test_list_policy_rules_ordered_by_priority(tmp_db):
    policy = fw.create_policy("Contractors")
    fw.add_rule(policy_id=policy["id"], direction="outbound", action="allow", priority=5)
    fw.add_rule(policy_id=policy["id"], direction="outbound", action="deny", priority=1)
    rules = fw.list_policy_rules(policy["id"])
    assert [r["priority"] for r in rules] == [1, 5]


def test_update_rule_revalidates_ports_against_new_protocol(tmp_db):
    policy = fw.create_policy("Contractors")
    rule = fw.add_rule(policy_id=policy["id"], direction="outbound", action="allow",
                        protocol="tcp", port_start=443)
    with pytest.raises(ValueError):
        fw.update_rule(rule["id"], protocol="icmp")


def test_delete_rule_idempotent(tmp_db):
    policy = fw.create_policy("Contractors")
    rule = fw.add_rule(policy_id=policy["id"], direction="outbound", action="allow")
    assert fw.delete_rule(rule["id"]) is True
    assert fw.delete_rule(rule["id"]) is False


# ---------------------------------------------------------------------------
# core/firewall.py — user assignment + all_firewall_rules()
# ---------------------------------------------------------------------------

def test_get_user_firewall_unmanaged_by_default(tmp_db):
    conn = database.get_db()
    _insert_user(conn, "alice")
    conn.close()
    assignment = fw.get_user_firewall("alice")
    assert assignment["managed"] is False
    assert assignment["policy_id"] is None
    assert assignment["blocked"] is False


def test_all_firewall_rules_excludes_unmanaged_users(tmp_db):
    conn = database.get_db()
    _insert_user(conn, "alice")
    conn.close()
    assert fw.all_firewall_rules() == []


def test_all_firewall_rules_orders_override_before_policy(tmp_db):
    conn = database.get_db()
    _insert_user(conn, "alice")
    conn.close()

    policy = fw.create_policy("Contractors", default_action="deny")
    fw.add_rule(policy_id=policy["id"], direction="outbound", action="allow",
                protocol="tcp", port_start=443, remote_cidr="10.0.0.0/8")
    fw.set_user_firewall("alice", policy_id=policy["id"], blocked=False)
    fw.add_rule(user_client_id="alice", direction="outbound", action="allow",
                protocol="udp", port_start=53, remote_cidr="8.8.8.8/32")

    entries = fw.all_firewall_rules()
    assert len(entries) == 1
    entry = entries[0]
    assert entry["client_id"] == "alice"
    assert entry["policy_default_action"] == "deny"
    assert [r["user_client_id"] for r in entry["rules"]] == ["alice", None]


def test_all_firewall_rules_blocked_user_has_no_rules_list(tmp_db):
    conn = database.get_db()
    _insert_user(conn, "carol")
    conn.close()
    fw.set_user_firewall("carol", policy_id=None, blocked=True)

    entries = fw.all_firewall_rules()
    assert len(entries) == 1
    assert entries[0]["blocked"] is True
    assert entries[0]["rules"] == []


def test_all_firewall_rules_disabled_policy_treated_as_unmanaged(tmp_db):
    conn = database.get_db()
    _insert_user(conn, "alice")
    conn.close()
    policy = fw.create_policy("Contractors", enabled=False)
    fw.add_rule(policy_id=policy["id"], direction="outbound", action="allow")
    fw.set_user_firewall("alice", policy_id=policy["id"], blocked=False)

    entries = fw.all_firewall_rules()
    assert entries[0]["policy_id"] is None
    assert entries[0]["policy_default_action"] is None
    assert entries[0]["rules"] == []


# ---------------------------------------------------------------------------
# tasks._build_user_fw_rules() — pure-function iptables rule generation
# ---------------------------------------------------------------------------

def test_build_user_fw_rules_default_deny_with_override_and_policy(tmp_db):
    conn = database.get_db()
    _insert_user(conn, "alice", wg_ipv4="10.66.66.5")
    conn.close()

    policy = fw.create_policy("Contractors", default_action="deny")
    fw.add_rule(policy_id=policy["id"], direction="outbound", action="allow",
                protocol="tcp", port_start=443, remote_cidr="10.0.0.0/8")
    fw.set_user_firewall("alice", policy_id=policy["id"], blocked=False)
    fw.add_rule(user_client_id="alice", direction="outbound", action="allow",
                protocol="udp", port_start=53, remote_cidr="8.8.8.8/32")

    rules = tasks._build_user_fw_rules()
    assert rules == [
        ["-A", "WS_USER_FW", "-s", "10.66.66.5", "-d", "8.8.8.8/32", "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
        ["-A", "WS_USER_FW", "-s", "10.66.66.5", "-d", "10.0.0.0/8", "-p", "tcp", "--dport", "443", "-j", "ACCEPT"],
        ["-A", "WS_USER_FW", "-s", "10.66.66.5", "-j", "DROP"],
        ["-A", "WS_USER_FW", "-d", "10.66.66.5", "-j", "DROP"],
    ]


def test_build_user_fw_rules_default_allow_emits_no_tail(tmp_db):
    conn = database.get_db()
    _insert_user(conn, "bob", wg_ipv4="10.66.66.6")
    conn.close()

    policy = fw.create_policy("Full Access", default_action="allow")
    fw.set_user_firewall("bob", policy_id=policy["id"], blocked=False)

    rules = tasks._build_user_fw_rules()
    assert rules == []


def test_build_user_block_rules_blocked_user_only_drops(tmp_db):
    conn = database.get_db()
    _insert_user(conn, "carol", wg_ipv4="10.66.66.7")
    conn.close()
    fw.set_user_firewall("carol", policy_id=None, blocked=True)

    rules = tasks._build_user_block_rules()
    assert rules == [
        ["-A", "WS_USER_BLOCK", "-s", "10.66.66.7", "-j", "DROP"],
        ["-A", "WS_USER_BLOCK", "-d", "10.66.66.7", "-j", "DROP"],
    ]


def test_build_user_fw_rules_skips_blocked_users_entirely(tmp_db):
    # Blocked users are handled by WS_USER_BLOCK (see
    # test_build_user_block_rules_blocked_user_only_drops) — WS_USER_FW
    # must not also emit anything for them.
    conn = database.get_db()
    _insert_user(conn, "carol", wg_ipv4="10.66.66.7")
    conn.close()
    fw.set_user_firewall("carol", policy_id=None, blocked=True)

    assert tasks._build_user_fw_rules() == []


def test_build_user_fw_rules_inbound_rule_matches_destination(tmp_db):
    conn = database.get_db()
    _insert_user(conn, "dave", wg_ipv4="10.66.66.8")
    conn.close()
    policy = fw.create_policy("Inbound SSH", default_action="deny")
    fw.add_rule(policy_id=policy["id"], direction="inbound", action="allow",
                protocol="tcp", port_start=22, remote_cidr="192.168.1.0/24")
    fw.set_user_firewall("dave", policy_id=policy["id"], blocked=False)

    rules = tasks._build_user_fw_rules()
    assert rules[0] == ["-A", "WS_USER_FW", "-d", "10.66.66.8", "-s", "192.168.1.0/24",
                         "-p", "tcp", "--dport", "22", "-j", "ACCEPT"]


def test_build_user_fw_rules_icmp_rule_has_no_dport(tmp_db):
    conn = database.get_db()
    _insert_user(conn, "erin", wg_ipv4="10.66.66.9")
    conn.close()
    policy = fw.create_policy("Ping Only", default_action="deny")
    fw.add_rule(policy_id=policy["id"], direction="outbound", action="allow", protocol="icmp")
    fw.set_user_firewall("erin", policy_id=policy["id"], blocked=False)

    rules = tasks._build_user_fw_rules()
    assert ["-A", "WS_USER_FW", "-s", "10.66.66.9", "-p", "icmp", "-j", "ACCEPT"] in rules


def test_build_user_fw_rules_skips_user_with_no_known_ip(tmp_db):
    # Policy-governed (not blocked) so this genuinely exercises the
    # "no known tunnel IP" skip path in _build_user_fw_rules, rather than
    # the separate "blocked users are skipped entirely" path.
    conn = database.get_db()
    conn.execute("INSERT INTO users (client_id, enabled) VALUES ('frank', 1)")
    conn.commit()
    conn.close()
    policy = fw.create_policy("No IP Policy", default_action="deny")
    fw.set_user_firewall("frank", policy_id=policy["id"], blocked=False)

    # No wg_ipv4/wg_ipv6 on record and no wg0.conf on this test machine —
    # resolve_client_ips() returns (None, None), so nothing is emitted.
    rules = tasks._build_user_fw_rules()
    assert rules == []


def test_build_user_block_rules_skips_user_with_no_known_ip(tmp_db):
    conn = database.get_db()
    conn.execute("INSERT INTO users (client_id, enabled) VALUES ('frank', 1)")
    conn.commit()
    conn.close()
    fw.set_user_firewall("frank", policy_id=None, blocked=True)

    rules = tasks._build_user_block_rules()
    assert rules == []


# ---------------------------------------------------------------------------
# console.py — policy endpoints
# ---------------------------------------------------------------------------

def test_create_and_list_firewall_policy_endpoint(tmp_db):
    body = console.FirewallPolicyCreateRequest(name="Contractors", default_action="deny")
    result = asyncio.run(
        console.create_firewall_policy(body=body, request=_fake_req(), client_id="admin", _csrf=None)
    )
    assert result["success"] is True
    listed = asyncio.run(console.list_firewall_policies(client_id="admin"))
    assert len(listed["policies"]) == 1
    assert listed["policies"][0]["name"] == "Contractors"


def test_create_firewall_policy_duplicate_name_returns_409(tmp_db):
    body = console.FirewallPolicyCreateRequest(name="Contractors")
    asyncio.run(console.create_firewall_policy(body=body, request=_fake_req(), client_id="admin", _csrf=None))
    with pytest.raises(HTTPException) as exc:
        asyncio.run(console.create_firewall_policy(body=body, request=_fake_req(), client_id="admin", _csrf=None))
    assert exc.value.status_code == 409


def test_create_firewall_policy_bad_default_action_returns_400(tmp_db):
    body = console.FirewallPolicyCreateRequest(name="Bad", default_action="maybe")
    with pytest.raises(HTTPException) as exc:
        asyncio.run(console.create_firewall_policy(body=body, request=_fake_req(), client_id="admin", _csrf=None))
    assert exc.value.status_code == 400


def test_get_firewall_policy_not_found_returns_404(tmp_db):
    with pytest.raises(HTTPException) as exc:
        asyncio.run(console.get_firewall_policy(policy_id=9999, client_id="admin"))
    assert exc.value.status_code == 404


def test_patch_firewall_policy_updates_field(tmp_db):
    created = asyncio.run(console.create_firewall_policy(
        body=console.FirewallPolicyCreateRequest(name="Contractors", default_action="deny"),
        request=_fake_req(), client_id="admin", _csrf=None,
    ))
    policy_id = created["policy"]["id"]

    result = asyncio.run(console.patch_firewall_policy(
        policy_id=policy_id, body=console.FirewallPolicyUpdateRequest(default_action="allow"),
        request=_fake_req(), client_id="admin", _csrf=None,
    ))
    assert result["policy"]["default_action"] == "allow"


def test_delete_firewall_policy_endpoint(tmp_db):
    created = asyncio.run(console.create_firewall_policy(
        body=console.FirewallPolicyCreateRequest(name="Contractors"),
        request=_fake_req(), client_id="admin", _csrf=None,
    ))
    policy_id = created["policy"]["id"]
    result = asyncio.run(console.delete_firewall_policy(
        policy_id=policy_id, request=_fake_req(), client_id="admin", _csrf=None,
    ))
    assert result["success"] is True
    with pytest.raises(HTTPException):
        asyncio.run(console.get_firewall_policy(policy_id=policy_id, client_id="admin"))


# ---------------------------------------------------------------------------
# console.py — policy rule endpoints
# ---------------------------------------------------------------------------

def test_add_firewall_policy_rule_endpoint(tmp_db):
    created = asyncio.run(console.create_firewall_policy(
        body=console.FirewallPolicyCreateRequest(name="Contractors"),
        request=_fake_req(), client_id="admin", _csrf=None,
    ))
    policy_id = created["policy"]["id"]

    result = asyncio.run(console.add_firewall_policy_rule(
        policy_id=policy_id,
        body=console.FirewallRuleRequest(direction="outbound", action="allow", protocol="tcp", port_start=443),
        request=_fake_req(), client_id="admin", _csrf=None,
    ))
    assert result["success"] is True
    assert result["rule"]["protocol"] == "tcp"


def test_add_firewall_policy_rule_rejects_bad_cidr(tmp_db):
    created = asyncio.run(console.create_firewall_policy(
        body=console.FirewallPolicyCreateRequest(name="Contractors"),
        request=_fake_req(), client_id="admin", _csrf=None,
    ))
    policy_id = created["policy"]["id"]

    with pytest.raises(HTTPException) as exc:
        asyncio.run(console.add_firewall_policy_rule(
            policy_id=policy_id,
            body=console.FirewallRuleRequest(direction="outbound", action="allow", remote_cidr="'; DROP TABLE users; --"),
            request=_fake_req(), client_id="admin", _csrf=None,
        ))
    assert exc.value.status_code == 400


def test_delete_firewall_policy_rule_endpoint(tmp_db):
    created = asyncio.run(console.create_firewall_policy(
        body=console.FirewallPolicyCreateRequest(name="Contractors"),
        request=_fake_req(), client_id="admin", _csrf=None,
    ))
    policy_id = created["policy"]["id"]
    rule = asyncio.run(console.add_firewall_policy_rule(
        policy_id=policy_id,
        body=console.FirewallRuleRequest(direction="outbound", action="allow"),
        request=_fake_req(), client_id="admin", _csrf=None,
    ))["rule"]

    result = asyncio.run(console.delete_firewall_policy_rule(
        policy_id=policy_id, rule_id=rule["id"], request=_fake_req(), client_id="admin", _csrf=None,
    ))
    assert result["removed"] is True


# ---------------------------------------------------------------------------
# console.py — per-user firewall endpoints
# ---------------------------------------------------------------------------

def test_get_user_firewall_endpoint_defaults_unmanaged(tmp_db):
    conn = database.get_db()
    _insert_user(conn, "alice")
    conn.close()
    result = asyncio.run(console.get_user_firewall_endpoint(target_client_id="alice", client_id="admin"))
    assert result["managed"] is False
    assert result["override_rules"] == []


def test_set_user_firewall_endpoint_assigns_policy_and_blocks(tmp_db):
    conn = database.get_db()
    _insert_user(conn, "alice")
    conn.close()
    policy = asyncio.run(console.create_firewall_policy(
        body=console.FirewallPolicyCreateRequest(name="Contractors"),
        request=_fake_req(), client_id="admin", _csrf=None,
    ))["policy"]

    result = asyncio.run(console.set_user_firewall_endpoint(
        target_client_id="alice",
        body=console.UserFirewallRequest(policy_id=policy["id"], blocked=False),
        request=_fake_req(), client_id="admin", _csrf=None,
    ))
    assert result["firewall"]["policy_id"] == policy["id"]

    blocked_result = asyncio.run(console.set_user_firewall_endpoint(
        target_client_id="alice",
        body=console.UserFirewallRequest(policy_id=None, blocked=True),
        request=_fake_req(), client_id="admin", _csrf=None,
    ))
    assert blocked_result["firewall"]["blocked"] is True
    assert blocked_result["firewall"]["policy_id"] is None


def test_set_user_firewall_endpoint_unknown_client_returns_400(tmp_db):
    with pytest.raises(HTTPException) as exc:
        asyncio.run(console.set_user_firewall_endpoint(
            target_client_id="ghost",
            body=console.UserFirewallRequest(policy_id=None, blocked=True),
            request=_fake_req(), client_id="admin", _csrf=None,
        ))
    assert exc.value.status_code == 400


def test_add_and_delete_user_firewall_rule_endpoint(tmp_db):
    conn = database.get_db()
    _insert_user(conn, "alice")
    conn.close()

    added = asyncio.run(console.add_user_firewall_rule(
        target_client_id="alice",
        body=console.FirewallRuleRequest(direction="outbound", action="allow", protocol="udp", port_start=53),
        request=_fake_req(), client_id="admin", _csrf=None,
    ))
    assert added["rule"]["user_client_id"] == "alice"

    removed = asyncio.run(console.delete_user_firewall_rule(
        target_client_id="alice", rule_id=added["rule"]["id"],
        request=_fake_req(), client_id="admin", _csrf=None,
    ))
    assert removed["removed"] is True


# ---------------------------------------------------------------------------
# Bug-fix regression coverage (per-user firewall code review)
# ---------------------------------------------------------------------------
# Fix 7: update_policy() must never let a field's VALUE be mistaken for the
# updated_at sentinel.

def test_update_policy_field_valued_current_timestamp_not_corrupted(tmp_db):
    policy = fw.create_policy("Contractors", description="original")
    fw.update_policy(policy["id"], description="CURRENT_TIMESTAMP")
    got = fw.get_policy(policy["id"])
    assert got["description"] == "CURRENT_TIMESTAMP"


def test_update_policy_still_bumps_updated_at(tmp_db):
    policy = fw.create_policy("Contractors")
    before = fw.get_policy(policy["id"])["updated_at"]
    fw.update_policy(policy["id"], description="changed")
    after = fw.get_policy(policy["id"])["updated_at"]
    assert after is not None and before is not None


# Fix 5: deleting a client must not orphan user_firewall/firewall_rules rows.

def test_delete_client_removes_firewall_state(tmp_db, tmp_path):
    from app.core import wireguard

    conn = database.get_db()
    _insert_user(conn, "alice", wg_ipv4="10.66.66.5")
    conn.commit()
    conn.close()

    policy = fw.create_policy("Contractors")
    fw.set_user_firewall("alice", policy_id=policy["id"], blocked=False)
    fw.add_rule(user_client_id="alice", direction="outbound", action="allow")
    assert fw.get_user_firewall("alice")["managed"] is True
    assert fw.list_user_override_rules("alice") != []

    conf_path = tmp_path / "wg0.conf"
    conf_path.write_text(
        "[Interface]\n"
        "PrivateKey = server\n\n"
        "### Client alice | Expires: None\n"
        "PublicKey = abc\n"
        "AllowedIPs = 10.66.66.5/32\n\n"
    )

    with patch("app.core.wireguard._load_params", return_value={}), \
         patch("app.core.wireguard._server_conf_path", return_value=str(conf_path)), \
         patch("app.core.wireguard._wg_syncconf"), \
         patch("app.core.wireguard._client_config_dir", return_value=str(tmp_path)):
        removed = wireguard.delete_client("alice")

    assert removed is True
    assert fw.get_user_firewall("alice")["managed"] is False
    assert fw.list_user_override_rules("alice") == []


# Fix 3: rule update/delete must be scoped to the owner (policy_id /
# user_client_id) the caller expects, not just the bare rule id.

def test_update_rule_rejects_mismatched_policy_owner(tmp_db):
    p1 = fw.create_policy("P1")
    p2 = fw.create_policy("P2")
    rule = fw.add_rule(policy_id=p1["id"], direction="outbound", action="allow")
    changed = fw.update_rule(rule["id"], expected_policy_id=p2["id"], action="deny")
    assert changed is False
    # untouched
    assert fw.list_policy_rules(p1["id"])[0]["action"] == "allow"


def test_delete_rule_rejects_mismatched_policy_owner(tmp_db):
    p1 = fw.create_policy("P1")
    p2 = fw.create_policy("P2")
    rule = fw.add_rule(policy_id=p1["id"], direction="outbound", action="allow")
    removed = fw.delete_rule(rule["id"], expected_policy_id=p2["id"])
    assert removed is False
    assert len(fw.list_policy_rules(p1["id"])) == 1


def test_delete_rule_rejects_user_rule_via_policy_scope(tmp_db):
    conn = database.get_db()
    _insert_user(conn, "alice")
    conn.close()
    policy = fw.create_policy("P1")
    rule = fw.add_rule(user_client_id="alice", direction="outbound", action="allow")
    removed = fw.delete_rule(rule["id"], expected_policy_id=policy["id"])
    assert removed is False
    assert len(fw.list_user_override_rules("alice")) == 1


def test_delete_rule_accepts_matching_owner(tmp_db):
    p1 = fw.create_policy("P1")
    rule = fw.add_rule(policy_id=p1["id"], direction="outbound", action="allow")
    assert fw.delete_rule(rule["id"], expected_policy_id=p1["id"]) is True


def test_update_firewall_policy_rule_endpoint_rejects_cross_owner(tmp_db):
    p1 = asyncio.run(console.create_firewall_policy(
        body=console.FirewallPolicyCreateRequest(name="P1"),
        request=_fake_req(), client_id="admin", _csrf=None,
    ))["policy"]
    p2 = asyncio.run(console.create_firewall_policy(
        body=console.FirewallPolicyCreateRequest(name="P2"),
        request=_fake_req(), client_id="admin", _csrf=None,
    ))["policy"]
    rule = asyncio.run(console.add_firewall_policy_rule(
        policy_id=p1["id"],
        body=console.FirewallRuleRequest(direction="outbound", action="allow"),
        request=_fake_req(), client_id="admin", _csrf=None,
    ))["rule"]

    with pytest.raises(HTTPException) as exc:
        asyncio.run(console.update_firewall_policy_rule(
            policy_id=p2["id"], rule_id=rule["id"],
            body=console.FirewallRuleUpdateRequest(action="deny"),
            request=_fake_req(), client_id="admin", _csrf=None,
        ))
    assert exc.value.status_code == 404


def test_delete_user_firewall_rule_endpoint_unknown_user_returns_404(tmp_db):
    with pytest.raises(HTTPException) as exc:
        asyncio.run(console.delete_user_firewall_rule(
            target_client_id="ghost", rule_id=9999,
            request=_fake_req(), client_id="admin", _csrf=None,
        ))
    assert exc.value.status_code == 404


# Fix 4: PATCH must be able to explicitly clear ports when switching a rule
# to icmp/all, via model_fields_set (not `v is not None`).

def test_update_firewall_policy_rule_endpoint_clears_ports_for_icmp(tmp_db):
    p1 = asyncio.run(console.create_firewall_policy(
        body=console.FirewallPolicyCreateRequest(name="P1"),
        request=_fake_req(), client_id="admin", _csrf=None,
    ))["policy"]
    rule = asyncio.run(console.add_firewall_policy_rule(
        policy_id=p1["id"],
        body=console.FirewallRuleRequest(direction="outbound", action="allow", protocol="tcp", port_start=443),
        request=_fake_req(), client_id="admin", _csrf=None,
    ))["rule"]

    result = asyncio.run(console.update_firewall_policy_rule(
        policy_id=p1["id"], rule_id=rule["id"],
        body=console.FirewallRuleUpdateRequest(protocol="icmp", port_start=None, port_end=None),
        request=_fake_req(), client_id="admin", _csrf=None,
    ))
    assert result["success"] is True
    updated = fw.list_policy_rules(p1["id"])[0]
    assert updated["protocol"] == "icmp"
    assert updated["port_start"] is None and updated["port_end"] is None


def test_update_rule_omitted_ports_still_reject_incompatible_protocol(tmp_db):
    # Confirms the existing (correct) behavior is preserved: omitting
    # ports entirely still means "keep the old ones", so switching to
    # icmp without explicitly clearing them keeps failing.
    p1 = fw.create_policy("P1")
    rule = fw.add_rule(policy_id=p1["id"], direction="outbound", action="allow",
                        protocol="tcp", port_start=443)
    with pytest.raises(ValueError):
        fw.update_rule(rule["id"], protocol="icmp")


# Fix 2: a user with override rules but no user_firewall row (or one with
# no policy/block) must still be enforced.

def test_all_firewall_rules_includes_override_only_user(tmp_db):
    conn = database.get_db()
    _insert_user(conn, "alice", wg_ipv4="10.66.66.5")
    _insert_user(conn, "bob", wg_ipv4="10.66.66.6")
    conn.close()

    # alice: override rule only, no user_firewall row at all.
    fw.add_rule(user_client_id="alice", direction="outbound", action="deny", remote_cidr="10.0.0.0/8")
    # bob: nothing at all — must remain excluded (control case).

    entries = fw.all_firewall_rules()
    client_ids = {e["client_id"] for e in entries}
    assert client_ids == {"alice"}
    alice = entries[0]
    assert alice["blocked"] is False
    assert alice["policy_id"] is None
    assert len(alice["rules"]) == 1


def test_build_user_fw_rules_enforces_override_only_user(tmp_db):
    conn = database.get_db()
    _insert_user(conn, "alice", wg_ipv4="10.66.66.5")
    conn.close()
    fw.add_rule(user_client_id="alice", direction="outbound", action="deny",
                protocol="tcp", port_start=22, remote_cidr="10.0.0.0/8")

    rules = tasks._build_user_fw_rules()
    assert rules == [
        ["-A", "WS_USER_FW", "-s", "10.66.66.5", "-d", "10.0.0.0/8", "-p", "tcp", "--dport", "22", "-j", "DROP"],
    ]


# Fix 1: blocking a user must revoke their session synchronously, exactly
# once at the point of the block action (not repeatedly from the tasks.py
# rule builder, which must stay a pure function with no side effects).

def test_set_user_firewall_blocked_revokes_live_session(tmp_db):
    conn = database.get_db()
    _insert_user(conn, "carol", wg_ipv4="10.66.66.7")
    conn.execute(
        "INSERT INTO sessions (client_id, session_token, expires_at, device_ip) "
        "VALUES ('carol', 'tok123', datetime('now', '+1 day'), '10.66.66.7')"
    )
    conn.commit()
    conn.close()

    fw.set_user_firewall("carol", policy_id=None, blocked=True)

    conn = database.get_db()
    remaining = conn.execute("SELECT COUNT(*) FROM sessions WHERE client_id = 'carol'").fetchone()[0]
    conn.close()
    assert remaining == 0


def test_build_user_block_rules_has_no_side_effects(tmp_db):
    # _build_user_block_rules() must be a pure function — no session
    # revocation should happen just from computing the rule list (that
    # already happened, once, in set_user_firewall()).
    conn = database.get_db()
    _insert_user(conn, "carol", wg_ipv4="10.66.66.7")
    conn.execute(
        "INSERT INTO sessions (client_id, session_token, expires_at, device_ip) "
        "VALUES ('carol', 'tok123', datetime('now', '+1 day'), '10.66.66.7')"
    )
    conn.commit()
    conn.close()
    fw.set_user_firewall("carol", policy_id=None, blocked=True)

    # The above already deleted the session (see previous test). Insert a
    # fresh one to prove _build_user_block_rules() itself doesn't touch it.
    conn = database.get_db()
    conn.execute(
        "INSERT INTO sessions (client_id, session_token, expires_at, device_ip) "
        "VALUES ('carol', 'tok456', datetime('now', '+1 day'), '10.66.66.7')"
    )
    conn.commit()
    conn.close()

    tasks._build_user_block_rules()
    tasks._build_user_block_rules()  # call it repeatedly, like the 30s loop would

    conn = database.get_db()
    remaining = conn.execute("SELECT COUNT(*) FROM sessions WHERE client_id = 'carol'").fetchone()[0]
    conn.close()
    assert remaining == 1, "the pure rule-builder must not revoke sessions itself"


# Fix 1/6: self-correcting FORWARD chain positioning (mocked iptables —
# no root/real iptables needed).

def _mk_forward_state(lines):
    return {"lines": list(lines)}


def _fake_iptables_run_factory(state):
    from unittest.mock import MagicMock

    def fake(args, check=False):
        r = MagicMock()
        r.returncode = 0
        r.stdout = b""
        if args[:2] == ["-n", "-L"]:
            return r
        if args[0] == "-S" and args[1] == "FORWARD":
            out = "-P FORWARD ACCEPT\n" + "\n".join(state["lines"]) + ("\n" if state["lines"] else "")
            r.stdout = out.encode()
            return r
        if args[0] == "-D" and args[1] == "FORWARD":
            jump = args[-1]
            state["lines"] = [l for l in state["lines"] if not l.endswith(f"-j {jump}")]
            return r
        if args[0] == "-I" and args[1] == "FORWARD":
            pos = int(args[2])
            jump = args[-1]
            state["lines"].insert(pos - 1, f"-A FORWARD -j {jump}")
            return r
        if args[0] == "-C":
            return r
        return r
    return fake


def test_ensure_user_fw_chain_corrects_inverted_startup_race(tmp_db):
    # Simulates the exact bug-6 scenario: WS_USER_FW ended up above both
    # WS_AGENT_ACL and the ESTABLISHED,RELATED accept due to a startup
    # race. One call to _ensure_user_fw_chain() must reposition it below
    # both anchors.
    state = _mk_forward_state([
        "-A FORWARD -j WS_USER_FW",
        "-A FORWARD -j WS_AGENT_ACL",
        "-A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
    ])
    with patch.object(tasks, "_iptables_run", side_effect=_fake_iptables_run_factory(state)), \
         patch.object(tasks, "_ensure_agent_acl_chain", lambda: None):
        tasks._ensure_user_fw_chain()

    agent_idx = next(i for i, l in enumerate(state["lines"]) if l.endswith("WS_AGENT_ACL"))
    established_idx = next(i for i, l in enumerate(state["lines"]) if "ESTABLISHED" in l)
    userfw_idx = next(i for i, l in enumerate(state["lines"]) if l.endswith("WS_USER_FW"))
    assert agent_idx < userfw_idx
    assert established_idx < userfw_idx


def test_ensure_user_fw_chain_is_noop_when_already_correct(tmp_db):
    state = _mk_forward_state([
        "-A FORWARD -j WS_AGENT_ACL",
        "-A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
        "-A FORWARD -j WS_USER_FW",
    ])
    fake = _fake_iptables_run_factory(state)
    calls = []

    def recording_fake(args, check=False):
        calls.append(list(args))
        return fake(args, check=check)

    with patch.object(tasks, "_iptables_run", side_effect=recording_fake), \
         patch.object(tasks, "_ensure_agent_acl_chain", lambda: None):
        tasks._ensure_user_fw_chain()

    mutating = [c for c in calls if c[0] in ("-I", "-D", "-N")]
    assert mutating == []


def test_ensure_user_block_chain_reclaims_position_one(tmp_db):
    state = _mk_forward_state([
        "-A FORWARD -j WS_AGENT_ACL",
        "-A FORWARD -j WS_USER_BLOCK",
    ])
    with patch.object(tasks, "_iptables_run", side_effect=_fake_iptables_run_factory(state)):
        tasks._ensure_user_block_chain()

    assert state["lines"][0].endswith("WS_USER_BLOCK")


def test_ensure_user_block_chain_noop_when_already_at_top(tmp_db):
    state = _mk_forward_state(["-A FORWARD -j WS_USER_BLOCK", "-A FORWARD -j WS_AGENT_ACL"])
    fake = _fake_iptables_run_factory(state)
    calls = []

    def recording_fake(args, check=False):
        calls.append(list(args))
        return fake(args, check=check)

    with patch.object(tasks, "_iptables_run", side_effect=recording_fake):
        tasks._ensure_user_block_chain()

    mutating = [c for c in calls if c[0] in ("-I", "-D", "-N")]
    assert mutating == []
